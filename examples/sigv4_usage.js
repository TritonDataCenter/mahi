/*
 * Copyright 2025 Edgecast Cloud LLC.
 * Example usage of SigV4 authentication with Mahi
 */

var http = require('http');
var crypto = require('crypto');

// Example: How S3 gateway would use Mahi for SigV4 authentication

function authenticateS3Request(req, res, next) {
    // Check if this is a SigV4 request
    var authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('AWS4-HMAC-SHA256')) {
        // Not a SigV4 request, handle with other auth methods
        return next();
    }

    // Call Mahi to verify the signature
    var mahiOptions = {
        hostname: 'mahi.example.com',
        port: 8080,
        path: '/aws-verify',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            // Forward all headers from original request
            'Authorization': req.headers.authorization,
            'X-Amz-Date': req.headers['x-amz-date'],
            'X-Amz-Content-Sha256': req.headers['x-amz-content-sha256'],
            'Host': req.headers.host
        }
    };

    var mahiReq = http.request(mahiOptions, function(mahiRes) {
        var body = '';
        mahiRes.on('data', function(chunk) {
            body += chunk;
        });
        
        mahiRes.on('end', function() {
            if (mahiRes.statusCode === 200) {
                var result = JSON.parse(body);
                // Authentication successful
                req.user = {
                    uuid: result.userUuid,
                    accessKeyId: result.accessKeyId
                };
                next();
            } else {
                // Authentication failed
                res.statusCode = mahiRes.statusCode;
                res.end(body);
            }
        });
    });

    mahiReq.on('error', function(err) {
        res.statusCode = 500;
        res.end('Authentication service error');
    });

    // Forward the request body if present
    if (req.body) {
        mahiReq.write(JSON.stringify(req.body));
    }
    mahiReq.end();
}

// Example: How to lookup a user by access key ID
function lookupUserByAccessKey(accessKeyId, callback) {
    var options = {
        hostname: 'mahi.example.com',
        port: 8080,
        path: '/aws-auth/' + accessKeyId,
        method: 'GET'
    };

    var req = http.request(options, function(res) {
        var body = '';
        res.on('data', function(chunk) {
            body += chunk;
        });
        
        res.on('end', function() {
            if (res.statusCode === 200) {
                callback(null, JSON.parse(body));
            } else {
                callback(new Error('User not found'));
            }
        });
    });

    req.on('error', callback);
    req.end();
}

// Example: Generate test SigV4 signature
function generateTestSignature(accessKeyId, secretKey, region, service) {
    var now = new Date();
    var timestamp = now.toISOString().replace(/[:\-]|\.\d{3}/g, '');
    var dateStamp = timestamp.substr(0, 8);
    
    var canonicalHeaders = 'host:s3.amazonaws.com\nx-amz-date:' + timestamp + '\n';
    var signedHeaders = 'host;x-amz-date';
    var payloadHash = 'UNSIGNED-PAYLOAD';
    
    var canonicalRequest = 'GET\n/\n\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + payloadHash;
    
    var credentialScope = dateStamp + '/' + region + '/' + service + '/aws4_request';
    var stringToSign = 'AWS4-HMAC-SHA256\n' + timestamp + '\n' + credentialScope + '\n' + 
                      crypto.createHash('sha256').update(canonicalRequest).digest('hex');
    
    function hmac(key, string) {
        return crypto.createHmac('sha256', key).update(string).digest();
    }
    
    var kDate = hmac('AWS4' + secretKey, dateStamp);
    var kRegion = hmac(kDate, region);
    var kService = hmac(kRegion, service);
    var kSigning = hmac(kService, 'aws4_request');
    var signature = hmac(kSigning, stringToSign).toString('hex');
    
    var authHeader = 'AWS4-HMAC-SHA256 Credential=' + accessKeyId + '/' + credentialScope + 
                    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
    
    return {
        'Authorization': authHeader,
        'X-Amz-Date': timestamp,
        'X-Amz-Content-Sha256': payloadHash
    };
}

module.exports = {
    authenticateS3Request: authenticateS3Request,
    lookupUserByAccessKey: lookupUserByAccessKey,
    generateTestSignature: generateTestSignature
};
