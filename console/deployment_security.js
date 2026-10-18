'use strict';

const fs = require('node:fs');
const net = require('node:net');

const MIN_PRODUCTION_KEY_BYTES = 32;
const MIN_PRODUCTION_KEY_CHARACTERS = 12;

function deploymentError(message) {
    return new Error(message);
}

function validateProductionKeys(env) {
    const entries = [
        ['viewer', env.EDR_READ_API_KEY],
        ['operator', env.EDR_INGEST_API_KEY],
        ['admin', env.EDR_ADMIN_API_KEY],
    ];
    for (const [role, key] of entries) {
        if (typeof key !== 'string' || Buffer.byteLength(key, 'utf8') < MIN_PRODUCTION_KEY_BYTES ||
            !/^[\x21-\x7e]+$/.test(key) ||
            new Set(key).size < MIN_PRODUCTION_KEY_CHARACTERS) {
            throw deploymentError(
                `production mode requires a strong, explicit ${role} API key ` +
                `(at least ${MIN_PRODUCTION_KEY_BYTES} printable ASCII bytes with ` +
                `${MIN_PRODUCTION_KEY_CHARACTERS} distinct characters)`);
        }
    }
    const keyValues = entries.map(([, key]) => key);
    if (new Set(keyValues).size !== keyValues.length)
        throw deploymentError('production mode requires different viewer, operator, and admin API keys');
}

function resolveDeploymentSecurity(env) {
    const mode = String(env.EDR_CONSOLE_MODE || 'development').trim().toLowerCase();
    if (mode !== 'development' && mode !== 'production')
        throw deploymentError('EDR_CONSOLE_MODE must be development or production');
    const production = mode === 'production';
    if (production) validateProductionKeys(env);

    const certPath = env.EDR_CONSOLE_TLS_CERT_FILE || '';
    const keyPath = env.EDR_CONSOLE_TLS_KEY_FILE || '';
    const proxyMode = String(env.EDR_CONSOLE_TLS_PROXY_MODE || '').trim().toLowerCase();
    if (proxyMode && proxyMode !== 'loopback')
        throw deploymentError('EDR_CONSOLE_TLS_PROXY_MODE only supports loopback');
    if (Boolean(certPath) !== Boolean(keyPath))
        throw deploymentError('HTTPS requires both EDR_CONSOLE_TLS_CERT_FILE and EDR_CONSOLE_TLS_KEY_FILE');
    if (proxyMode && certPath)
        throw deploymentError('configure either direct HTTPS or loopback TLS-proxy mode, not both');

    let tlsOptions = null;
    if (certPath && keyPath) {
        try {
            const cert = fs.readFileSync(certPath);
            const key = fs.readFileSync(keyPath);
            if (!cert.length || !key.length)
                throw deploymentError('TLS certificate and key files must not be empty');
            tlsOptions = { cert, key, minVersion: 'TLSv1.2' };
        } catch (error) {
            if (error && error.message.startsWith('TLS certificate')) throw error;
            throw deploymentError(`could not read configured TLS certificate or key: ${error.message}`);
        }
    }
    if (production && !tlsOptions && !proxyMode)
        throw deploymentError(
            'production mode requires HTTPS certificate/key files or EDR_CONSOLE_TLS_PROXY_MODE=loopback');

    return Object.freeze({
        mode,
        production,
        tlsOptions,
        tlsProxyMode: proxyMode,
        usesHttps: Boolean(tlsOptions),
    });
}

function isLoopbackHost(host) {
    const value = String(host).toLowerCase().replace(/^\[|\]$/g, '');
    if (value === 'localhost') return true;
    const version = net.isIP(value);
    if (version === 4) return Number(value.split('.')[0]) === 127;
    return version === 6 && value === '::1';
}

function isNumericLoopbackHost(host) {
    const value = String(host).replace(/^\[|\]$/g, '');
    return net.isIP(value) !== 0 && isLoopbackHost(value);
}

function assertBindAllowed(deployment, keys, host) {
    const loopback = isLoopbackHost(host);
    if (deployment.tlsProxyMode === 'loopback' && !isNumericLoopbackHost(host)) {
        throw deploymentError(
            'loopback TLS-proxy mode must bind to a numeric loopback address (127.0.0.0/8 or ::1)');
    }
    if (!loopback && (!keys.ingest || !keys.read))
        throw deploymentError('non-loopback binding requires ingest and read API keys');
    if (!loopback && !deployment.usesHttps)
        throw deploymentError('non-loopback HTTP bind is not allowed; configure HTTPS certificate and key');
}

module.exports = {
    MIN_PRODUCTION_KEY_BYTES,
    resolveDeploymentSecurity,
    assertBindAllowed,
    isLoopbackHost,
};
