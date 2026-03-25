'use strict';
const { obfuscate } = require('../obfuscator.js');

function injectProtections(source, { key, hwid, hwidValue }) {
    let prefix = '';

    if (hwid && hwidValue) {
        const escaped = hwidValue.replace(/"/g, '\\"');
        prefix += `
local _ICE_HWID = tostring(game:GetService("Players").LocalPlayer.UserId)
local _ICE_HWID_LOCK = "${escaped}"
if _ICE_HWID ~= _ICE_HWID_LOCK then
    error("[ICE] Unauthorized hardware. This script is locked.", 0)
    while true do game:GetService("RunService").Heartbeat:Wait() end
end
`;
    }

    if (key && key.trim() !== '') {
        const escaped = key.trim().replace(/"/g, '\\"');
        prefix += `
local _ICE_KEY_REQUIRED = "${escaped}"
local _ICE_KEY_INPUT = getgenv and getgenv()._ICE_KEY or ""
if _ICE_KEY_INPUT ~= _ICE_KEY_REQUIRED then
    error("[ICE] Invalid key. Set getgenv()._ICE_KEY = 'YOUR_KEY' before executing.", 0)
end
`;
    }

    return prefix + source;
}

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { source, key, hwid, hwidValue } = req.body;

        if (!source || typeof source !== 'string' || source.trim() === '') {
            return res.status(400).json({ error: 'No source code provided.' });
        }

        if (source.length > 200000) {
            return res.status(400).json({ error: 'File too large (max 200KB).' });
        }

        const injected = injectProtections(source, {
            key:        key        || '',
            hwid:       hwid       || false,
            hwidValue:  hwidValue  || '',
        });

        const result = obfuscate(injected);

        return res.status(200).json({ result });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Obfuscation failed: ' + err.message });
    }
};

