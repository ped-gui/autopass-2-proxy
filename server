// ===== AutoPass Proxy Server =====
// Servidor proxy completo para API BlueFleet com validações, cache e logging
// Compatível com Fly.io

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';

config();

// ===== CONFIGURAÇÃO =====
const CONFIG = {
  port: parseInt(process.env.PORT || '8080', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  
  bluefleet: {
    apiUrl: process.env.BLUEFLEET_API_URL || 'https://api.bluefleet.com.br',
    clientId: process.env.BLUEFLEET_CLIENT_ID_PROD || '',
    clientSecret: process.env.BLUEFLEET_CLIENT_SECRET_PROD || '',
    tokenUrl: 'https://auth.bluefleet.com.br/connect/token',
  },
  
  supabase: {
    url: process.env.SUPABASE_URL || '',
    serviceKey: process.env.SUPABASE_SERVICE_ROLE_KEY || '',
    jwtSecret: process.env.SUPABASE_JWT_SECRET || '',
  },
  
  app: {
    environment: process.env.ENVIRONMENT || 'prod',
    targetEnv: process.env.TARGET_ENV || 'db3',
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['*'],
  },
  
  rateLimit: {
    windowMs: 60 * 1000, // 1 minuto
    max: 100, // 100 requests por minuto por IP
  },
};

// Validação de variáveis obrigatórias
const requiredEnvVars = [
  'BLUEFLEET_CLIENT_ID_PROD',
  'BLUEFLEET_CLIENT_SECRET_PROD',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_JWT_SECRET',
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`❌ Missing required environment variable: ${envVar}`);
  }
}

// ===== SUPABASE CLIENT =====
const supabase = createClient(CONFIG.supabase.url, CONFIG.supabase.serviceKey);

// ===== ALLOWLIST DE ENDPOINTS =====
const ALLOWED_ENDPOINTS = [
  // GET endpoints
  { path: /^\/contract-item-request\/search/, method: 'GET' },
  { path: /^\/contract-item-request\/\d+$/, method: 'GET' },
  { path: /^\/contract-item-request\/\d+\/files$/, method: 'GET' },
  { path: /^\/contract-item-request\/\d+\/order$/, method: 'GET' },
  { path: /^\/contract-item-request\/\d+\/order\/[^\/]+$/, method: 'GET' },
  { path: /^\/purchase-order/, method: 'GET' },
  { path: /^\/purchase-order\/\d+$/, method: 'GET' },
  { path: /^\/financial-invoice/, method: 'GET' },
  { path: /^\/provider/, method: 'GET' },
  { path: /^\/provider\/\d+$/, method: 'GET' },
  { path: /^\/vehicle/, method: 'GET' },
  { path: /^\/bank/, method: 'GET' },
  
  // POST endpoints
  { path: /^\/contract-item-request\/\d+\/waiting-checkin$/, method: 'POST' },
  { path: /^\/contract-item-request\/\d+\/file$/, method: 'POST' },
  { path: /^\/contract-item-request\/\d+\/order$/, method: 'POST' },
  { path: /^\/contract-item-request\/\d+\/waiting-quoting$/, method: 'POST' },
  { path: /^\/contract-item-request\/\d+\/ongoing-services$/, method: 'POST' },
  { path: /^\/contract-item-request\/\d+\/waiting-vehicle-pickup$/, method: 'POST' },
  { path: /^\/contract-item-request\/\d+\/scheduling-date$/, method: 'POST' },
  { path: /^\/financial-invoice$/, method: 'POST', requiresPermission: 2 },
  { path: /^\/financial-invoice\/\d+\/file$/, method: 'POST', requiresPermission: 2 },
];

const IMAGE_EXTENSIONS = [
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico',
  '.tiff', '.tif', '.heic', '.heif',
  '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wmv', '.flv',
];

// ===== FUNÇÕES UTILITÁRIAS =====

function log(level, message, ...args) {
  const timestamp = new Date().toISOString();
  const levelSymbols = {
    info: 'ℹ️',
    warn: '⚠️',
    error: '❌',
    debug: '🔍',
    success: '✅',
  };
  const symbol = levelSymbols[level] || 'ℹ️';
  console.log(`[${timestamp}] ${symbol} ${message}`, ...args);
}

function extractJWTData(authHeader) {
  if (!authHeader) {
    log('warn', '[AUTH] No Authorization header present');
    return {};
  }

  try {
    const token = authHeader.replace('Bearer ', '').trim();
    const decoded = jwt.verify(token, CONFIG.supabase.jwtSecret);
    
    const authId = decoded.sub || decoded.user_id;
    const providerId = decoded.user_metadata?.provider_id;
    const userType = decoded.user_metadata?.user_type;
    
    if (authId) log('success', `[AUTH] User authenticated: ${authId}`);
    if (providerId) log('success', `[AUTH] Provider ID: ${providerId}`);
    if (userType) log('success', `[AUTH] User Type: ${userType}`);
    
    return { authId, providerId, userType };
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      log('error', '[AUTH] Invalid JWT:', error.message);
    } else if (error instanceof jwt.TokenExpiredError) {
      log('error', '[AUTH] JWT expired');
    } else {
      log('error', '[AUTH] Error verifying JWT:', error);
    }
    return {};
  }
}

function normalizeEndpoint(path) {
  return path.replace(/\/\d+(?=\/|$)/g, '/{id}');
}

function isEndpointAllowed(path, method) {
  const pathWithoutQuery = path.split('?')[0];
  
  for (const endpoint of ALLOWED_ENDPOINTS) {
    if (endpoint.method === method && endpoint.path.test(pathWithoutQuery)) {
      log('success', `[ALLOWLIST] ✅ Endpoint allowed: ${method} ${pathWithoutQuery}${
        endpoint.requiresPermission ? ` (requires permission: ${endpoint.requiresPermission})` : ''
      }`);
      
      return {
        allowed: true,
        requiresPermission: endpoint.requiresPermission,
      };
    }
  }
  
  log('warn', `[ALLOWLIST] ❌ Endpoint blocked: ${method} ${pathWithoutQuery}`);
  return { allowed: false };
}

function extractContractItemRequestId(path, body) {
  const pathMatch = path.match(/\/contract-item-request\/(\d+)/);
  if (pathMatch) return pathMatch[1];
  
  if (body) {
    return body.contractItemRequestId || body.contract_item_request_id || null;
  }
  
  return null;
}

function extractProviderId(body) {
  if (!body) return null;
  return body.providerId || body.provider_id || null;
}

function isContractItemRequestEndpoint(path) {
  const regex = /^\/contract-item-request\/(\d+)(?:\/)?$/;
  const match = path.match(regex);
  return match ? { match: true, contractItemRequestId: match[1] } : { match: false };
}

function isOrderEndpoint(path) {
  const regex = /\/contract-item-request\/([^\/]+)\/order\/([^\/?\s]+)/;
  const match = path.match(regex);
  return match
    ? { match: true, contractItemRequestId: match[1], orderRequestOrderId: match[2] }
    : { match: false };
}

function isFilesEndpoint(path) {
  const regex = /^\/contract-item-request\/(\d+)\/files(?:\/)?$/;
  const match = path.match(regex);
  return match ? { match: true, contractItemRequestId: match[1] } : { match: false };
}

function isImageFile(filename) {
  if (!filename) return false;
  const lowerFilename = filename.toLowerCase();
  return IMAGE_EXTENSIONS.some((ext) => lowerFilename.endsWith(ext));
}

function filterImageFiles(responseBody) {
  if (!responseBody?.data || !Array.isArray(responseBody.data)) {
    log('debug', '[FILTER-IMAGES] Response data not an array, skipping filter');
    return responseBody;
  }

  log('info', `[FILTER-IMAGES] Filtering ${responseBody.data.length} files`);
  
  const originalCount = responseBody.data.length;
  const filteredData = responseBody.data.filter((file) => {
    if (!file.filename) {
      log('debug', '[FILTER-IMAGES] File without filename, removing');
      return false;
    }
    
    const isImage = isImageFile(file.filename);
    if (!isImage) {
      log('debug', `[FILTER-IMAGES] Removing non-image: ${file.filename}`);
    }
    return isImage;
  });

  log('success', `[FILTER-IMAGES] ✅ Filtered: ${originalCount} → ${filteredData.length} (removed: ${
    originalCount - filteredData.length
  })`);

  return { ...responseBody, data: filteredData };
}

function filterResponseByProviderId(responseBody, userProviderId, userType) {
  // Se user_type é "internal", não aplica filtro
  if (userType === 'internal') {
    log('debug', '[FILTER] User type is "internal", skipping filter');
    return responseBody;
  }

  if (!userProviderId) {
    log('debug', '[FILTER] No user provider_id, skipping filter');
    return responseBody;
  }

  if (!responseBody?.data) {
    log('debug', '[FILTER] No data in response, skipping filter');
    return responseBody;
  }

  const userProviderIdStr = String(userProviderId);

  // CASO 1: data é um OBJETO ÚNICO
  if (!Array.isArray(responseBody.data) && typeof responseBody.data === 'object') {
    const item = responseBody.data;
    
    if (!item.providerId && item.providerId !== 0) {
      log('debug', '[FILTER] Single object without providerId, keeping it');
      return responseBody;
    }
    
    const itemProviderId = String(item.providerId);
    
    if (itemProviderId !== userProviderIdStr) {
      log('warn', `[FILTER] ❌ BLOCKING single object with providerId: ${itemProviderId} (user: ${userProviderIdStr})`);
      
      return {
        data: null,
        code: 'FORBIDDEN',
        message: 'Você não tem permissão para acessar este recurso',
        isSuccess: false,
      };
    }
    
    log('success', `[FILTER] ✅ Single object matches user providerId: ${userProviderIdStr}`);
    return responseBody;
  }

  // CASO 2: data é um ARRAY
  if (!Array.isArray(responseBody.data)) {
    log('debug', '[FILTER] Response data is not an array or object, skipping filter');
    return responseBody;
  }

  log('info', `[FILTER] Filtering ${responseBody.data.length} items by provider_id: ${userProviderId}`);
  
  const originalCount = responseBody.data.length;
  const filteredData = responseBody.data.filter((item) => {
    if (!item.providerId && item.providerId !== 0) {
      return true; // Backward compatibility
    }
    
    const itemProviderId = String(item.providerId);
    const shouldKeep = itemProviderId === userProviderIdStr;
    
    if (!shouldKeep) {
      log('debug', `[FILTER] Removing item with providerId: ${itemProviderId}`);
    }
    
    return shouldKeep;
  });

  log('success', `[FILTER] ✅ Filtered: ${originalCount} → ${filteredData.length} (removed: ${
    originalCount - filteredData.length
  })`);

  return { ...responseBody, data: filteredData };
}

// ===== FUNÇÕES DE SUPABASE =====

async function checkUserPermission(authId, requiredPermission) {
  try {
    log('info', `[PERMISSIONS] Checking user ${authId} for permission ${requiredPermission}`);
    
    const { data, error } = await supabase
      .from('v_users_complete')
      .select('permissions')
      .eq('auth_id', authId)
      .single();

    if (error) {
      log('error', '[PERMISSIONS] Error fetching user permissions:', error);
      return false;
    }

    if (!data) {
      log('warn', '[PERMISSIONS] User not found');
      return false;
    }

    const permissions = data.permissions || [];
    const permissionsAsNumbers = permissions.map((p) =>
      typeof p === 'string' ? parseInt(p, 10) : p
    );
    
    const hasPermission = permissionsAsNumbers.includes(requiredPermission);
    
    log('info', `[PERMISSIONS] User ${authId} has permission ${requiredPermission}: ${hasPermission}`);
    
    return hasPermission;
  } catch (error) {
    log('error', '[PERMISSIONS] Exception checking permissions:', error);
    return false;
  }
}

async function logRequest(logData) {
  try {
    log('debug', '[LOG] ==================== LOGGING REQUEST ====================');
    
    const endpointNormalized = normalizeEndpoint(logData.endpoint);

    const insertData = {
      auth_id: logData.authId || null,
      endpoint: logData.endpoint,
      endpoint_normalized: endpointNormalized,
      method: logData.method,
      request_body: logData.requestBody || null,
      response_status: logData.responseStatus || null,
      response_body: logData.responseBody || null,
      ip: logData.ip || null,
      error_message: logData.errorMessage || null,
      contract_item_request_id: logData.contractItemRequestId || null,
      provider_id: logData.providerId || null,
      error_context: logData.errorContext || null,
    };

    const { error } = await supabase.from('api_proxy_logs').insert(insertData);

    if (error) {
      log('error', '[LOG] ❌ Failed to insert log:', error);
    } else {
      log('success', '[LOG] ✅ Log inserted successfully');
    }
  } catch (error) {
    log('error', '[LOG] ❌ Exception while logging:', error);
  }
}

async function updateCacheContractItem(contractItemRequestId, responseData) {
  try {
    log('info', `[CACHE-CONTRACT] Updating cache for contract_item_request_id: ${contractItemRequestId}`);
    
    const data = responseData?.data;
    if (!data) {
      log('warn', '[CACHE-CONTRACT] No data in response, skipping cache update');
      return;
    }

    const { data: existingCache, error: selectError } = await supabase
      .from('tab_cache')
      .select('*')
      .eq('contract_item_request_id', contractItemRequestId)
      .single();

    if (selectError && selectError.code !== 'PGRST116') {
      log('error', '[CACHE-CONTRACT] Error checking existing cache:', selectError);
      return;
    }

    const cacheData = {
      contract_item_request_id: contractItemRequestId,
      vehicle_model_name: data.vehicleModelName || null,
      provider_id: data.providerId?.toString() || null,
      vehicle_id: data.vehicleId?.toString() || null,
      request_created_at: data.createdAt || null,
      updated_at: new Date().toISOString(),
    };

    if (existingCache) {
      log('debug', `[CACHE-CONTRACT] Updating existing cache record: ${existingCache.id}`);
      
      const { error: updateError } = await supabase
        .from('tab_cache')
        .update(cacheData)
        .eq('id', existingCache.id);

      if (updateError) {
        log('error', '[CACHE-CONTRACT] Failed to update cache:', updateError);
      } else {
        log('success', '[CACHE-CONTRACT] ✅ Cache updated successfully');
      }
    } else {
      log('debug', '[CACHE-CONTRACT] Creating new cache record');
      
      const { error: insertError } = await supabase
        .from('tab_cache')
        .insert({ ...cacheData, orders: null });

      if (insertError) {
        log('error', '[CACHE-CONTRACT] Failed to insert cache:', insertError);
      } else {
        log('success', '[CACHE-CONTRACT] ✅ Cache created successfully');
      }
    }
  } catch (error) {
    log('error', '[CACHE-CONTRACT] Exception while updating cache:', error);
  }
}

async function updateCacheOrder(contractItemRequestId, responseData) {
  try {
    log('info', `[CACHE-ORDER] Updating cache for contract_item_request_id: ${contractItemRequestId}`);
    
    const data = responseData?.data;
    if (!data) {
      log('warn', '[CACHE-ORDER] No data in response, skipping cache update');
      return;
    }

    if (data.purchaseOrderApprovalStatusName !== 'Aprovada') {
      log('info', `[CACHE-ORDER] Order status is '${data.purchaseOrderApprovalStatusName}', skipping cache`);
      return;
    }

    const newOrder = {
      contractItemRequestOrderId: data.contractItemRequestOrderId,
      total: data.total,
    };

    const { data: existingCache, error: selectError } = await supabase
      .from('tab_cache')
      .select('*')
      .eq('contract_item_request_id', contractItemRequestId)
      .single();

    if (selectError && selectError.code !== 'PGRST116') {
      log('error', '[CACHE-ORDER] Error checking existing cache:', selectError);
      return;
    }

    let ordersArray = [];

    if (existingCache) {
      if (existingCache.orders) {
        ordersArray = Array.isArray(existingCache.orders)
          ? existingCache.orders
          : [existingCache.orders];
      }

      const existingOrderIndex = ordersArray.findIndex(
        (order) => order.contractItemRequestOrderId === newOrder.contractItemRequestOrderId
      );

      if (existingOrderIndex !== -1) {
        log('debug', `[CACHE-ORDER] Updating existing order ${newOrder.contractItemRequestOrderId}`);
        ordersArray[existingOrderIndex] = newOrder;
      } else {
        log('debug', `[CACHE-ORDER] Adding new order ${newOrder.contractItemRequestOrderId}`);
        ordersArray.push(newOrder);
      }

      log('debug', `[CACHE-ORDER] Updating cache with ${ordersArray.length} orders`);
      
      const { error: updateError } = await supabase
        .from('tab_cache')
        .update({
          orders: ordersArray,
          provider_id: data.providerId?.toString() || existingCache.provider_id,
          vehicle_id: data.vehicleId?.toString() || existingCache.vehicle_id,
          updated_at: new Date().toISOString(),
        })
        .eq('id', existingCache.id);

      if (updateError) {
        log('error', '[CACHE-ORDER] Failed to update cache:', updateError);
      } else {
        log('success', '[CACHE-ORDER] ✅ Cache updated successfully');
      }
    } else {
      log('debug', '[CACHE-ORDER] Creating new cache record with first order');
      ordersArray = [newOrder];

      const { error: insertError } = await supabase
        .from('tab_cache')
        .insert({
          contract_item_request_id: contractItemRequestId,
          orders: ordersArray,
          provider_id: data.providerId?.toString() || null,
          vehicle_id: data.vehicleId?.toString() || null,
          vehicle_model_name: null,
          updated_at: new Date().toISOString(),
        });

      if (insertError) {
        log('error', '[CACHE-ORDER] Failed to insert cache:', insertError);
      } else {
        log('success', '[CACHE-ORDER] ✅ Cache created successfully');
      }
    }
  } catch (error) {
    log('error', '[CACHE-ORDER] Exception while updating cache:', error);
  }
}

// ===== BLUEFLEET TOKEN MANAGEMENT =====

async function getBlueFleetToken() {
  log('debug', '[TOKEN] Checking database for cached token...');
  
  const { data: tokenData, error: fetchError } = await supabase
    .from('api_tokens')
    .select('*')
    .eq('environment', CONFIG.app.environment)
    .single();

  if (fetchError && fetchError.code !== 'PGRST116') {
    log('error', '[TOKEN] Database error:', fetchError);
  }

  if (tokenData?.access_token) {
    const expiresAt = new Date(tokenData.expires_at).getTime();
    const now = Date.now();
    
    if (now < expiresAt) {
      const timeLeft = Math.floor((expiresAt - now) / 1000);
      log('success', `[TOKEN] ✅ Using cached token (expires in ${timeLeft}s)`);
      return tokenData.access_token;
    }
    
    log('info', '[TOKEN] Token expired, renewing...');
  } else {
    log('info', '[TOKEN] No token found, fetching new one...');
  }

  const { token, expiresAt } = await fetchNewBlueFleetToken();
  
  const { error: upsertError } = await supabase
    .from('api_tokens')
    .upsert(
      {
        environment: CONFIG.app.environment,
        access_token: token,
        expires_at: new Date(expiresAt).toISOString(),
      },
      { onConflict: 'environment' }
    );

  if (upsertError) {
    log('error', '[TOKEN] Failed to save token:', upsertError);
  } else {
    log('success', '[TOKEN] ✅ Token saved to database');
  }

  return token;
}

async function fetchNewBlueFleetToken() {
  log('info', '[TOKEN] Fetching new token from BlueFleet API');
  
  if (!CONFIG.bluefleet.clientId || !CONFIG.bluefleet.clientSecret) {
    throw new Error('BLUEFLEET_CLIENT_ID or BLUEFLEET_CLIENT_SECRET not configured');
  }
  
  // Tenta com Basic Auth primeiro
  try {
    const basicAuth = Buffer.from(
      `${CONFIG.bluefleet.clientId}:${CONFIG.bluefleet.clientSecret}`
    ).toString('base64');
    
    log('debug', '[TOKEN] Trying Basic Auth...');
    
    const response = await fetch(CONFIG.bluefleet.tokenUrl, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });

    if (response.ok) {
      const data = await response.json();
      
      if (!data.access_token) {
        throw new Error('access_token not found in response');
      }
      
      const expiresAt = Date.now() + (data.expires_in - 60) * 1000;
      log('success', `[TOKEN] ✅ Token obtained, expires in ${data.expires_in}s`);
      
      return { token: data.access_token, expiresAt };
    }

    log('warn', '[TOKEN] Basic Auth failed, trying alternative method...');
  } catch (error) {
    log('error', '[TOKEN] Basic Auth error:', error);
  }

  // Método alternativo (credentials no body)
  log('debug', '[TOKEN] Trying credentials in body...');
  
  const bodyParams = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CONFIG.bluefleet.clientId,
    client_secret: CONFIG.bluefleet.clientSecret,
  });

  const response = await fetch(CONFIG.bluefleet.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: bodyParams.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    log('error', '[TOKEN] Failed to get token:', errorText);
    throw new Error(`Failed to get token: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  
  if (!data.access_token) {
    throw new Error('access_token not found in response');
  }
  
  const expiresAt = Date.now() + (data.expires_in - 60) * 1000;
  log('success', `[TOKEN] ✅ Token obtained, expires in ${data.expires_in}s`);
  
  return { token: data.access_token, expiresAt };
}

// ===== EXPRESS APP =====

const app = express();

// Middlewares de segurança e performance
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (CONFIG.app.corsOrigins.includes('*')) {
      return callback(null, true);
    }

    if (CONFIG.app.corsOrigins.includes(origin)) {
      return callback(null, true);
    }

    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-autopass-env'],
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: CONFIG.rateLimit.windowMs,
  max: CONFIG.rateLimit.max,
  message: {
    error: 'Too many requests',
    message: 'Rate limit exceeded. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api', limiter);

// ===== ROUTES =====

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: CONFIG.app.environment,
    version: '2.0.0',
  });
});

// Metrics endpoint (básico)
app.get('/metrics', (req, res) => {
  res.status(200).send('# AutoPass Proxy Metrics\n');
});

// Proxy handler principal
app.all('/api/*', async (req, res) => {
  const startTime = Date.now();
  let parsedRequestBody = null;

  try {
    const clientIp =
      req.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
      req.headers['x-real-ip']?.toString() ||
      req.ip ||
      'unknown';

    // Extrai dados do JWT
    const { authId, providerId: userProviderId, userType } = extractJWTData(req.headers.authorization);

    // Extrai path
    let path = req.path.replace(/^\/api/, '');
    if (!path.startsWith('/')) {
      path = '/' + path;
    }

    const pathWithoutQuery = path.split('?')[0];
    const fullPath = req.url.replace(/^\/api/, '');

    log('info', `[REQUEST] ${req.method} ${fullPath}`);

    // VALIDAÇÃO DE ALLOWLIST
    const endpointCheck = isEndpointAllowed(pathWithoutQuery, req.method);

    if (!endpointCheck.allowed) {
      log('warn', `[ALLOWLIST] Rejecting blocked endpoint: ${req.method} ${pathWithoutQuery}`);

      await logRequest({
        authId,
        endpoint: fullPath,
        method: req.method,
        responseStatus: 403,
        ip: clientIp,
        errorMessage: 'Endpoint not allowed',
        errorContext: {
          blocked_endpoint: pathWithoutQuery,
          blocked_method: req.method,
        },
      });

      return res.status(403).json({
        error: 'Endpoint not allowed',
        message: 'This endpoint is not accessible through the proxy',
        code: 'ENDPOINT_BLOCKED',
      });
    }

    // VALIDAÇÃO DE PERMISSÕES
    if (endpointCheck.requiresPermission) {
      if (!authId) {
        log('warn', '[PERMISSIONS] Rejecting - no auth_id');

        await logRequest({
          authId,
          endpoint: fullPath,
          method: req.method,
          responseStatus: 401,
          ip: clientIp,
          errorMessage: 'Authentication required',
          errorContext: {
            required_permission: endpointCheck.requiresPermission,
          },
        });

        return res.status(401).json({
          error: 'Authentication required',
          message: 'This endpoint requires authentication',
          code: 'AUTHENTICATION_REQUIRED',
        });
      }

      const hasPermission = await checkUserPermission(authId, endpointCheck.requiresPermission);

      if (!hasPermission) {
        log('warn', `[PERMISSIONS] User lacks permission ${endpointCheck.requiresPermission}`);

        await logRequest({
          authId,
          endpoint: fullPath,
          method: req.method,
          responseStatus: 403,
          ip: clientIp,
          errorMessage: 'Insufficient permissions',
          errorContext: {
            required_permission: endpointCheck.requiresPermission,
          },
        });

        return res.status(403).json({
          error: 'Insufficient permissions',
          message: 'Você não tem permissão para acessar este recurso',
          code: 'PERMISSION_DENIED',
        });
      }

      log('success', `[PERMISSIONS] ✅ Permission check passed for user ${authId}`);
    }

    // Verificações de endpoints específicos
    const contractItemEndpointMatch = isContractItemRequestEndpoint(pathWithoutQuery);
    const orderEndpointMatch = isOrderEndpoint(pathWithoutQuery);
    const filesEndpointMatch = isFilesEndpoint(pathWithoutQuery);

    // Parse request body
    if (req.method !== 'GET' && req.body) {
      parsedRequestBody = req.body;
    }

    // Extrai IDs úteis
    const contractItemRequestId =
      orderEndpointMatch.contractItemRequestId ||
      contractItemEndpointMatch.contractItemRequestId ||
      filesEndpointMatch.contractItemRequestId ||
      extractContractItemRequestId(fullPath, parsedRequestBody);

    const providerId = extractProviderId(parsedRequestBody);

    // Obtém token da BlueFleet
    const token = await getBlueFleetToken();

    // Prepara requisição para BlueFleet
    const targetUrl = `${CONFIG.bluefleet.apiUrl}${fullPath}`;
    log('info', `[TARGET] Calling: ${targetUrl} [env: ${CONFIG.app.targetEnv}]`);

    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'x-autopass-env': CONFIG.app.targetEnv,
    };

    if (req.headers.authorization) {
      headers['x-user-jwt'] = req.headers.authorization.replace('Bearer ', '');
    }

    // Faz requisição
    const response = await fetch(targetUrl, {
      method: req.method,
      headers,
      body: req.method !== 'GET' && parsedRequestBody ? JSON.stringify(parsedRequestBody) : undefined,
    });

    const responseStatus = response.status;
    log('info', `[RESPONSE] ${responseStatus} for ${req.method} ${fullPath} (${Date.now() - startTime}ms)`);

    const responseText = await response.text();
    let parsedResponseBody;

    try {
      parsedResponseBody = responseText ? JSON.parse(responseText) : null;
    } catch {
      parsedResponseBody = responseText;
    }

    // FILTRAGEM POR PROVIDER ID
    let filteredResponseBody = parsedResponseBody;
    if (responseStatus === 200 && parsedResponseBody?.isSuccess) {
      filteredResponseBody = filterResponseByProviderId(parsedResponseBody, userProviderId, userType);
    }

    // FILTRAGEM DE IMAGENS NO ENDPOINT DE FILES
    if (
      req.method === 'GET' &&
      filesEndpointMatch.match &&
      responseStatus === 200 &&
      filteredResponseBody?.isSuccess
    ) {
      log('info', '[MAIN] Applying image filter for files endpoint');
      filteredResponseBody = filterImageFiles(filteredResponseBody);
    }

    // CACHE PARA CONTRACT ITEM REQUEST
    if (
      req.method === 'GET' &&
      contractItemEndpointMatch.match &&
      responseStatus === 200 &&
      filteredResponseBody?.isSuccess &&
      contractItemEndpointMatch.contractItemRequestId
    ) {
      updateCacheContractItem(contractItemEndpointMatch.contractItemRequestId, filteredResponseBody).catch(
        (err) => {
          log('error', '[CACHE-CONTRACT] Error in background cache update:', err);
        }
      );
    }

    // CACHE PARA ORDER
    if (
      req.method === 'GET' &&
      orderEndpointMatch.match &&
      responseStatus === 200 &&
      filteredResponseBody?.isSuccess &&
      orderEndpointMatch.contractItemRequestId
    ) {
      updateCacheOrder(orderEndpointMatch.contractItemRequestId, filteredResponseBody).catch((err) => {
        log('error', '[CACHE-ORDER] Error in background cache update:', err);
      });
    }

    // LOGGING
    const shouldLog = req.method === 'POST' || (req.method === 'GET' && responseStatus >= 400);

    if (shouldLog) {
      const isError = responseStatus >= 400;

      await logRequest({
        authId,
        endpoint: fullPath,
        method: req.method,
        requestBody: parsedRequestBody,
        responseStatus,
        responseBody: filteredResponseBody,
        ip: clientIp,
        errorMessage: isError ? `HTTP ${responseStatus}` : null,
        contractItemRequestId,
        providerId,
        errorContext: isError
          ? {
              target_url: targetUrl,
              duration_ms: Date.now() - startTime,
            }
          : null,
      });
    }

    // Retorna resposta
    return res.status(responseStatus).json(filteredResponseBody);
  } catch (error) {
    log('error', '[ERROR]', error);

    const fullPath = req.url.replace(/^\/api/, '');

    await logRequest({
      authId: extractJWTData(req.headers.authorization).authId,
      endpoint: fullPath,
      method: req.method,
      requestBody: parsedRequestBody,
      responseStatus: 500,
      ip:
        req.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
        req.ip ||
        'unknown',
      errorMessage: error.message,
      contractItemRequestId: extractContractItemRequestId(fullPath, parsedRequestBody),
      providerId: extractProviderId(parsedRequestBody),
      errorContext: {
        error_stack: error.stack,
        error_name: error.name,
        duration_ms: Date.now() - startTime,
      },
    });

    return res.status(500).json({
      error: error.message,
      code: 'INTERNAL_SERVER_ERROR',
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
  });
});

// Error handler
app.use((err, req, res, next) => {
  log('error', '[ERROR]', err);
  
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

// Inicia servidor
app.listen(CONFIG.port, () => {
  log('success', `🚀 AutoPass Proxy Server running on port ${CONFIG.port}`);
  log('info', `Environment: ${CONFIG.nodeEnv}`);
  log('info', `Target Environment: ${CONFIG.app.targetEnv}`);
  log('info', `CORS Origins: ${CONFIG.app.corsOrigins.join(', ')}`);
});

// Graceful shutdown
const shutdown = (signal) => {
  log('info', `${signal} received, shutting down gracefully...`);
  process.exit(0);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
```
