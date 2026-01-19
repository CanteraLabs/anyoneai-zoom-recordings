// supabase/functions/get-video-url/index.ts
// Edge Function para generar URLs pre-firmadas de S3

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Función para generar URL pre-firmada usando AWS Signature V4
async function generatePresignedUrl(
  bucket: string,
  key: string,
  region: string,
  accessKeyId: string,
  secretAccessKey: string,
  expiresIn: number = 3600
): Promise<string> {
  const host = `${bucket}.s3.${region}.amazonaws.com`
  const datetime = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '')
  const date = datetime.slice(0, 8)
  
  const credential = `${accessKeyId}/${date}/${region}/s3/aws4_request`
  
  const params = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': datetime,
    'X-Amz-Expires': expiresIn.toString(),
    'X-Amz-SignedHeaders': 'host',
  })

  const canonicalRequest = [
    'GET',
    '/' + key.split('/').map(encodeURIComponent).join('/'),
    params.toString(),
    `host:${host}`,
    '',
    'host',
    'UNSIGNED-PAYLOAD'
  ].join('\n')

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    datetime,
    `${date}/${region}/s3/aws4_request`,
    await sha256(canonicalRequest)
  ].join('\n')

  const signingKey = await getSignatureKey(secretAccessKey, date, region, 's3')
  const signature = await hmacHex(signingKey, stringToSign)

  params.set('X-Amz-Signature', signature)

  return `https://${host}/${key.split('/').map(encodeURIComponent).join('/')}?${params.toString()}`
}

async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

async function hmac(key: ArrayBuffer, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  return await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message))
}

async function hmacHex(key: ArrayBuffer, message: string): Promise<string> {
  const result = await hmac(key, message)
  return Array.from(new Uint8Array(result))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

async function getSignatureKey(
  key: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const kDate = await hmac(new TextEncoder().encode('AWS4' + key), dateStamp)
  const kRegion = await hmac(kDate, region)
  const kService = await hmac(kRegion, service)
  const kSigning = await hmac(kService, 'aws4_request')
  return kSigning
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Obtener configuración de variables de entorno
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const awsAccessKeyId = Deno.env.get('AWS_ACCESS_KEY_ID')!
    const awsSecretAccessKey = Deno.env.get('AWS_SECRET_ACCESS_KEY')!
    const awsRegion = Deno.env.get('AWS_REGION') || 'us-east-2'
    const s3Bucket = Deno.env.get('S3_BUCKET') || 'anyoneai-zoom-recordings'

    // Verificar autenticación
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: 'Missing authorization header' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Crear cliente de Supabase
    const supabase = createClient(supabaseUrl, supabaseServiceKey)

    // Obtener usuario del token
    const token = authHeader.replace('Bearer ', '')
    const { data: { user }, error: authError } = await supabase.auth.getUser(token)

    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: 'Invalid or expired token' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Verificar si el usuario tiene acceso
    const { data: hasAccess, error: accessError } = await supabase
      .rpc('has_video_access', { user_email: user.email })

    if (accessError) {
      console.error('Access check error:', accessError)
      return new Response(
        JSON.stringify({ error: 'Error checking access permissions' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!hasAccess) {
      return new Response(
        JSON.stringify({ error: 'Access denied. You do not have permission to view videos.' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Obtener el s3_key del body
    const { s3_key, recording_id } = await req.json()

    let videoKey = s3_key

    // Si viene recording_id en lugar de s3_key, buscarlo en la tabla
    if (!videoKey && recording_id) {
      const { data: recording, error: recordingError } = await supabase
        .from('zoom_recordings')
        .select('s3_key')
        .eq('id', recording_id)
        .single()

      if (recordingError || !recording) {
        return new Response(
          JSON.stringify({ error: 'Recording not found' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      videoKey = recording.s3_key
    }

    if (!videoKey) {
      return new Response(
        JSON.stringify({ error: 'Missing s3_key or recording_id' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Generar URL pre-firmada (válida por 1 hora)
    const presignedUrl = await generatePresignedUrl(
      s3Bucket,
      videoKey,
      awsRegion,
      awsAccessKeyId,
      awsSecretAccessKey,
      3600 // 1 hora
    )

    // Log de acceso (opcional - para auditoría)
    try {
      await supabase.from('video_access_log').insert({
        user_email: user.email,
        s3_key: videoKey,
        accessed_at: new Date().toISOString()
      })
    } catch (logError) {
      // Ignorar si la tabla de log no existe
      console.log('Log insert skipped (table may not exist)')
    }

    return new Response(
      JSON.stringify({ 
        url: presignedUrl,
        expires_in: 3600,
        message: 'URL válida por 1 hora'
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )

  } catch (error) {
    console.error('Error:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})
