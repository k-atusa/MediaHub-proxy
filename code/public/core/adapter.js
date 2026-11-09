// Backend network and encryption adapter !! CHANGE ADAPTER FOR OTHER VERSIONS !!
import { SHA3256, SymMaster, Masker, HashMaster } from '../engine/Bencrypt.js';
import { EncodeCfg, DecodeCfg, Opsec, DecodeInt } from '../engine/Opsec.js';
import { NormPW, Encode64, Decode64 } from '../engine/Bencode.js';
import { ToHex, FromHex, ShowNotice, DownloadProgressController, SafeSession } from './utils.js';
import { Drive } from './drive.js';

// ===== Common Constants and Helpers =====
const mask = new Masker();
const secretPepper = "_PROJECT_WHY_MEDIAHUB_PEPPER_2026_!@#$";
const appInfos = ["MediaHub Proxy", "1.6.0", "Proxy Streaming & File Sharing Client"];
const sessionVaultKey = '__k7mediahub_web_session__';
const kekHexRegex = /^[0-9a-fA-F]{64}$/;

// Get user PID from store-key (pos 0 to 16, 16B)
const getUserPid = (key) => {
    if (!key) return '';
    return ToHex(SHA3256(key).slice(0, 16));
};

// Get or generate session KEK (stored in window.name)
const getOrGenerateSessionKek = () => {
    let hex = window.name;
    if (typeof hex === 'string' && kekHexRegex.test(hex)) {
        return hex;
    }
    const rand = new Uint8Array(32);
    crypto.getRandomValues(rand);
    hex = ToHex(rand);
    rand.fill(0);
    window.name = hex;
    return hex;
};

// Import session KEK from hex string to Web Crypto Key
const importSessionKek = async (hexKey) => {
    const raw = FromHex(hexKey);
    const key = await crypto.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    raw.fill(0);
    return key;
};

// Backend network and encryption adapter
export class AdapterService {
    // Initialize adapter with window origin
    constructor() {
        this.serverUrl = window.location.origin;
        this.RequiresServiceWorker = false;
        this._activeStreamIds = new Set();
        this._streamPids = new Set();
        this._streamEpoch = 0;
    }

    // ===== Basic Functions =====
    // Retrieve saved user credentials
    async GetSavedCredentials() {
        return null;
    }

    // Persist user credentials
    async SaveCredentials(username, password) { }

    // Fetch server notification text
    async FetchNotice() {
        try {
            const res = await fetch(`${this.serverUrl}/api/notice`);
            if (!res.ok) return "";
            const data = await res.json();
            return data.notice || "";
        } catch {
            return "";
        }
    }

    // Display application info dialog
    async ShowAppInfo() {
        const lines = [`${appInfos[0]} v${appInfos[1]}`, '', `${appInfos[2]}`];
        await ShowNotice(lines.join('\n'), "About MediaHub", "info");
    }

    // ===== User Authentication =====
    // Derive userhash PID and masked masterkey
    async DeriveKeys(username, password) {
        const pwBytes = NormPW(password);
        const saltBytes = SHA3256(new TextEncoder().encode(username + secretPepper));
        const hm = new HashMaster("arg2st");
        const [storeKey, userKey] = await hm.KDF(pwBytes, saltBytes);
        const userHash = getUserPid(storeKey);
        const maskedKey = mask.XOR(userKey);
        userKey.fill(0);
        return { userHash, maskedKey };
    }

    // Check if user account exists on server
    async CheckUserExists(userHash) {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`);
        return res.status !== 404;
    }

    // Register user account on server
    async RegisterUser(userHash, inviteCode = "") {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`, {
            method: "POST",
            headers: inviteCode ? { "X-Invite-Code": inviteCode } : {},
            body: new Uint8Array(0)
        });
        if (!res.ok) {
            if (res.status === 403) throw new Error("Invalid invite code");
            throw new Error(`Registration failed (HTTP ${res.status})`);
        }
    }

    // Delete user account data on server
    async DeleteUserData(userHash) {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`, {
            method: "DELETE",
            headers: { "X-User-Hash": userHash }
        });
        if (!res.ok) throw new Error(`Failed to delete account (HTTP ${res.status})`);
    }

    // ===== Metadata Operations =====
    // Fetch and decrypt folder map
    async LoadUserData(userHash, maskedUserKey) {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`);
        if (res.status === 404) return {};
        if (!res.ok) throw new Error(`Failed to load userdata (HTTP ${res.status})`);

        const rawUk = mask.XOR(maskedUserKey);
        const sm = new SymMaster("gcm1", rawUk);
        rawUk.fill(0);

        const enc = new Uint8Array(await res.arrayBuffer());
        if (enc.length === 0) return {};

        const dec = await sm.DeBin(enc);
        const map = DecodeCfg(dec);
        dec.fill(0);
        return map;
    }

    // Encrypt and persist folder map
    async SaveUserData(userHash, rawFolderMap, maskedUserKey, oldHash = "") {
        const rawUk = mask.XOR(maskedUserKey);
        const sm = new SymMaster("gcm1", rawUk);
        rawUk.fill(0);

        const bin = EncodeCfg(rawFolderMap);
        const enc = await sm.EnBin(bin);
        bin.fill(0);

        const headers = { "X-User-Hash": oldHash || userHash };
        if (oldHash) headers["X-Old-Hash"] = oldHash;

        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`, {
            method: "POST",
            headers,
            body: enc
        });
        enc.fill(0);

        if (!res.ok) throw new Error(`Failed to save userdata (HTTP ${res.status})`);
    }

    // Fetch and decrypt file map
    async LoadFolderMeta(folderId, maskedFolderKey) {
        // If accessed through a share session, bypass folder meta fetch
        if (SafeSession.GetItem("isShareSession") === "true") {
            return {};
        }

        const res = await fetch(`${this.serverUrl}/api/storage/${folderId}/names`);
        if (res.status === 404) return {};
        if (!res.ok) throw new Error(`Failed to load folder map (HTTP ${res.status})`);

        const rawFk = mask.XOR(maskedFolderKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const enc = new Uint8Array(await res.arrayBuffer());
        if (enc.length === 0) return {};

        const dec = await sm.DeBin(enc);
        const map = DecodeCfg(dec);
        dec.fill(0);
        return map;
    }

    // Encrypt and persist file map
    async SaveFolderMeta(folderId, rawFilesMap, maskedFolderKey, userHash = "") {
        const rawFk = mask.XOR(maskedFolderKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const bin = EncodeCfg(rawFilesMap);
        const enc = await sm.EnBin(bin);
        bin.fill(0);

        const headers = {};
        if (userHash) headers["X-User-Hash"] = userHash;

        const res = await fetch(`${this.serverUrl}/api/storage/${folderId}/names`, {
            method: "POST",
            headers,
            body: enc
        });
        enc.fill(0);

        if (!res.ok) throw new Error(`Failed to save folder map (HTTP ${res.status})`);
    }

    // Delete file map
    async DeleteFolderMeta(folderId, userHash = "") {
        const headers = {};
        if (userHash) headers["X-User-Hash"] = userHash;

        const res = await fetch(`${this.serverUrl}/api/storage/${folderId}/names`, {
            method: "DELETE",
            headers
        });
        if (!res.ok && res.status !== 404) {
            throw new Error(`Failed to delete folder meta (HTTP ${res.status})`);
        }
    }

    // Trim orphan files of folder
    async TrimFolder(folderId, activePids, userHash = "") {
        const headers = { "Content-Type": "application/json" };
        if (userHash) headers["X-User-Hash"] = userHash;

        const res = await fetch(`${this.serverUrl}/api/trim/${folderId}`, {
            method: "POST",
            headers,
            body: JSON.stringify(activePids)
        });
        if (!res.ok) throw new Error(`Trim failed (HTTP ${res.status})`);
        return await res.text();
    }

    // ===== Media Operations =====
    // Download and decrypt media payload to blob URL
    async LoadMediaBlob(folderId, filePid, maskedFileKey, origSize = 0, mimeType = "application/octet-stream", onProgress = null) {
        // Direct download from proxy share endpoint if accessed via share session
        const isShare = SafeSession.GetItem("isShareSession") === "true";
        const shareId = SafeSession.GetItem("shareId");
        if (isShare && shareId) {
            const res = await fetch(`${this.serverUrl}/api/share/download/${shareId}`);
            if (res.ok) {
                const blob = await res.blob();
                return URL.createObjectURL(blob);
            }
        }

        const downloadChunkSize = 2 * 1048576;
        const url = `${this.serverUrl}/api/media/${folderId}/${filePid}/dat`;

        // Fetch a range with up to 3 attempts from the same offset
        const fetchChunk = async (start, end, allowFull = false) => {
            let lastErr;
            for (let attempt = 1; attempt <= 3; attempt++) {
                try {
                    // Fetch media chunk
                    const res = await fetch(url, {
                        headers: { 'Range': `bytes=${start}-${end}` }
                    });
                    if (res.status !== 206 && !(allowFull && res.status === 200)) {
                        throw new Error(`Failed to download media chunk (HTTP ${res.status})`);
                    }

                    // Download media chunk
                    const chunk = new Uint8Array(await res.arrayBuffer());
                    const contentRange = res.headers.get('Content-Range');
                    if (res.status === 206) {
                        const match = contentRange?.match(/^bytes (\d+)-(\d+)\/(\d+)$/);
                        if (!match || Number(match[1]) !== start || Number(match[2]) !== start + chunk.length - 1 || chunk.length !== Math.min(end - start + 1, Number(match[3]) - start)) {
                            throw new Error(`Invalid media chunk at offset ${start}`);
                        }
                    }
                    return { chunk, totalSize: contentRange ? Number(contentRange.split('/')[1]) : chunk.length };
                } catch (err) {
                    lastErr = err;
                    console.warn(`Download chunk at offset ${start} attempt ${attempt} failed:`, err);
                    if (attempt < 3) await new Promise(r => setTimeout(r, 300 * attempt));
                }
            }
            throw lastErr;
        };

        // Fetch first chunk to determine total file size from Content-Range
        const first = await fetchChunk(0, downloadChunkSize - 1, true);
        const totalSize = first.totalSize;
        const enc = new Uint8Array(totalSize);
        enc.set(first.chunk, 0);
        let downloaded = first.chunk.length;
        if (onProgress) {
            onProgress({ phase: 'downloading', loaded: downloaded, total: totalSize, percent: Math.round((downloaded / totalSize) * 100) });
        }

        // Assemble full ciphertext buffer from range chunks
        while (downloaded < totalSize) {
            const rangeEnd = Math.min(downloaded + downloadChunkSize, totalSize) - 1;
            const { chunk } = await fetchChunk(downloaded, rangeEnd);
            enc.set(chunk, downloaded);
            downloaded += chunk.length;
            if (onProgress) {
                onProgress({ phase: 'downloading', loaded: downloaded, total: totalSize, percent: Math.round((downloaded / totalSize) * 100) });
            }
        }

        // Decrypt assembled ciphertext using gcmx1 chunked stream decryption
        if (onProgress) {
            onProgress({ phase: 'decrypting', loaded: totalSize, total: totalSize, percent: 100 });
        }
        const rawFk = mask.XOR(maskedFileKey);
        const sm = new SymMaster("gcmx1", rawFk.slice(0, 32));
        rawFk.fill(0);

        // Strip random padding added during upload using AfterSize(origSize)
        let expectedEncSize = enc.length;
        if (typeof origSize === 'number' && origSize >= 0) {
            const calculated = sm.AfterSize(origSize);
            if (calculated > 0 && calculated <= enc.length) {
                expectedEncSize = calculated;
            }
        }
        const cipherData = enc.subarray(0, expectedEncSize);

        // Decrypt media data
        const dec = await sm.DeBin(cipherData);
        const unpadded = (origSize > 0 && dec.length >= origSize) ? dec.slice(0, origSize) : dec;
        const blob = new Blob([unpadded], { type: mimeType });
        dec.fill(0);
        if (onProgress) {
            onProgress({ phase: 'complete', loaded: totalSize, total: totalSize, percent: 100 });
        }
        return URL.createObjectURL(blob);
    }

    // Download, decrypt, and trigger browser file save
    async DownloadFile(folderId, filePid, maskedFileKey, fileName, origSize = 0) {
        const toast = new DownloadProgressController(fileName);
        try {
            const blobUrl = await this.LoadMediaBlob(
                folderId,
                filePid,
                maskedFileKey,
                origSize,
                "application/octet-stream",
                (p) => toast.update(p)
            );
            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
        } catch (err) {
            toast.fail(err);
            throw err;
        }
    }

    // Delete media binary and thumbnail
    async DeleteMedia(folderId, filePid, userHash = "") {
        const headers = {};
        if (userHash) headers["X-User-Hash"] = userHash;
        await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/dat`, {
            method: "DELETE",
            headers
        });
        await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/thumb`, {
            method: "DELETE",
            headers
        });
    }

    // ===== Thumbnail =====
    // Load and decrypt thumbnail blob URL
    async LoadThumbnailUrl(folderId, filePid, maskedFileKey) {
        const res = await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/thumb`);
        if (!res.ok) return null;

        const rawFk = mask.XOR(maskedFileKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const enc = new Uint8Array(await res.arrayBuffer());
        if (enc.length === 0) return null;
        try { // thumbnail is JPEG image
            const dec = await sm.DeBin(enc);
            const blob = new Blob([dec], { type: "image/jpeg" });
            dec.fill(0);
            return URL.createObjectURL(blob);
        } catch (err) {
            console.warn("Failed to decrypt thumbnail:", err);
            return null;
        }
    }

    // Generate JPEG thumbnail from image File
    async MakeImageThumb(file) {
        try {
            const bmp = await createImageBitmap(file);
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const ratio = bmp.width / bmp.height;
            if (ratio >= 0.6666 && ratio <= 1.5) { // rectangle image
                if (bmp.width >= bmp.height) {
                    canvas.width = 256;
                    canvas.height = Math.round(256 / ratio);
                } else {
                    canvas.height = 256;
                    canvas.width = Math.round(256 * ratio);
                }
                ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
            } else { // extreme ratio image
                const size = Math.min(bmp.width, bmp.height);
                canvas.width = 256;
                canvas.height = 256;
                ctx.drawImage(bmp, 0, 0, size, size, 0, 0, 256, 256);
            }
            bmp.close();
            return new Promise(r => canvas.toBlob(r, 'image/jpeg', 0.7));
        } catch {
            return null;
        }
    }

    // Generate JPEG thumbnail from video File
    MakeVideoThumb(file) {
        return new Promise((resolve) => {
            const video = document.createElement('video');
            video.preload = 'metadata';
            video.muted = true;
            video.playsInline = true;
            video.src = URL.createObjectURL(file);
            video.onloadeddata = () => video.currentTime = 1;
            video.onseeked = () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                const ratio = video.videoWidth / video.videoHeight;
                if (video.videoWidth >= video.videoHeight) {
                    canvas.width = 256;
                    canvas.height = Math.round(256 / ratio);
                } else {
                    canvas.height = 256;
                    canvas.width = Math.round(256 * ratio);
                }
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                canvas.toBlob((b) => {
                    URL.revokeObjectURL(video.src);
                    resolve(b);
                }, 'image/jpeg', 0.7);
            };
            video.onerror = () => {
                URL.revokeObjectURL(video.src);
                resolve(null);
            };
        });
    }

    // ===== Streaming =====
    // Register streaming credentials with proxy and return streaming endpoint URL
    async GetStreamUrl(folderId, filePid, maskedFileKey, origSize, fileName) {
        const isShare = SafeSession.GetItem("isShareSession") === "true";
        const shareId = SafeSession.GetItem("shareId");

        let bodyPayload;
        if (isShare && shareId) {
            bodyPayload = {
                shareId: shareId,
                fileName: fileName || SafeSession.GetItem("shareFileName") || "video.mp4",
                originalSize: origSize || Number(SafeSession.GetItem("shareOrigSize")) || 0
            };
        } else {
            const rawFk = mask.XOR(maskedFileKey);
            const hexKey = ToHex(rawFk);
            rawFk.fill(0);

            bodyPayload = {
                folderId,
                filePid,
                fileKey: hexKey,
                originalSize: origSize,
                fileName: fileName || "media"
            };
        }

        const res = await fetch(`${this.serverUrl}/api/stream/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyPayload)
        });

        if (!res.ok) {
            throw new Error(`Failed to register proxy streaming session (HTTP ${res.status})`);
        }

        const data = await res.json();
        if (data.sessionId) {
            this._activeStreamIds.add(data.sessionId);
        }
        return data.streamUrl;
    }

    // Register video streaming credentials (retained for interface compatibility)
    async RegisterStreaming(folderId, filePid, maskedFileKey, origSize, fileName) {
        try {
            await this.GetStreamUrl(folderId, filePid, maskedFileKey, origSize, fileName);
            return true;
        } catch {
            return false;
        }
    }

    // Release registrations for active streams
    ReleaseStreaming() {
        this._streamEpoch++;
        for (const sessionId of this._activeStreamIds) {
            fetch(`${this.serverUrl}/api/stream/${sessionId}`, { method: 'DELETE' }).catch(() => {});
        }
        this._activeStreamIds.clear();
        this._streamPids.clear();
    }

    // ===== Sharing =====
    // Generate shareable file link (Proxy version: registers keyless share session on proxy)
    async CreateShareLink(folderId, filePid, maskedFileKey = null, fileName = null, origSize = 0) {
        if (!maskedFileKey && Drive?.flsMap) {
            for (const [name, meta] of Object.entries(Drive.flsMap)) {
                if (meta?.filePid === filePid && meta?.fileKey) {
                    maskedFileKey = meta.fileKey;
                    if (!fileName) fileName = name;
                    if (!origSize && meta.origSize) origSize = meta.origSize;
                    break;
                }
            }
        }

        // Automatic fallback: extract filename and size from Drive.flsMap if missing
        if (!fileName && Drive?.flsMap) {
            const targetPid = String(filePid).toLowerCase();
            for (const [name, meta] of Object.entries(Drive.flsMap)) {
                if (meta && typeof meta === 'object') {
                    const matchPid = meta.filePid && String(meta.filePid).toLowerCase() === targetPid;
                    if (matchPid) {
                        fileName = name;
                        if (!origSize && meta.origSize) origSize = meta.origSize;
                        break;
                    }
                }
            }
        }

        let rawFk = null;
        if (maskedFileKey) {
            rawFk = mask.XOR(maskedFileKey);
        } else if (Drive?.flsMap) {
            for (const [name, meta] of Object.entries(Drive.flsMap)) {
                if (name === fileName && meta?.fileKey) {
                    rawFk = mask.XOR(meta.fileKey);
                    break;
                }
            }
        }

        if (!rawFk) {
            return `${this.serverUrl || window.location.origin}/viewer?f=${encodeURIComponent(folderId)}&p=${encodeURIComponent(filePid)}`;
        }

        const hexKey = ToHex(rawFk);
        rawFk.fill(0);

        try {
            const res = await fetch(`${this.serverUrl}/api/share/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    folderId,
                    filePid,
                    fileKey: hexKey,
                    originalSize: origSize,
                    fileName: fileName || filePid
                })
            });

            if (!res.ok) {
                return `${this.serverUrl || window.location.origin}/viewer?f=${encodeURIComponent(folderId)}&p=${encodeURIComponent(filePid)}`;
            }

            const data = await res.json();
            return `${this.serverUrl || window.location.origin}${data.shareUrl}`;
        } catch {
            return `${this.serverUrl || window.location.origin}/viewer?f=${encodeURIComponent(folderId)}&p=${encodeURIComponent(filePid)}`;
        }
    }

    // Check if it is a public route (for Proxy version: handles keyless share sessions)
    async IsPublicRoute(path, query) {
        if (path === '/viewer' && query?.s) {
            SafeSession.SetItem("isShareSession", "true");
            SafeSession.SetItem("shareId", query.s);

            try {
                const res = await fetch(`${this.serverUrl}/api/share/info?s=${encodeURIComponent(query.s)}`);
                if (res.ok) {
                    const info = await res.json();
                    SafeSession.SetItem("activeFolderId", info.folderId);
                    SafeSession.SetItem("shareFilePid", info.filePid);
                    SafeSession.SetItem("shareFileName", info.fileName);
                    SafeSession.SetItem("shareOrigSize", String(info.origSize || 0));

                    if (info.fileKey) {
                        const rawKey = FromHex(info.fileKey);
                        const maskedKey = mask.XOR(rawKey);
                        rawKey.fill(0);
                        SafeSession.SetItem("shareMaskedKey", ToHex(maskedKey));
                    }

                    if (typeof document !== 'undefined') {
                        document.title = `${info.fileName} - MediaHub`;
                        setTimeout(() => {
                            const txName = document.getElementById('txName');
                            if (txName) txName.textContent = info.fileName;
                        }, 50);
                    }
                }
            } catch (err) {
                console.warn("Failed to fetch share info from proxy:", err);
            }
            return true;
        }

        if (SafeSession.GetItem("isShareSession") === "true") {
            SafeSession.RemoveItem("isShareSession");
            SafeSession.RemoveItem("shareId");
            SafeSession.RemoveItem("shareFilePid");
            SafeSession.RemoveItem("shareFileName");
            SafeSession.RemoveItem("shareOrigSize");
            SafeSession.RemoveItem("shareMaskedKey");
        }
        return false;
    }

    // Retrieve viewer capabilities (for share session, only allow downloading)
    GetViewerCapabilities(isShared = false) {
        const isShareSession = SafeSession.GetItem("isShareSession") === "true";
        if (isShareSession || isShared) {
            return {
                canStream: true,
                canDownload: true,
                canShare: false,
                canRename: false,
                canDelete: false
            };
        }
        return {
            canStream: true,
            canDownload: true,
            canShare: true,
            canRename: true,
            canDelete: true
        };
    }

    // Export password-encrypted folder share token
    async ExportShareToken(folderName, maskedKey, password) {
        if (!password) return null;
        const rawKey = mask.XOR(maskedKey);
        const op = new Opsec();
        op.Smsg = folderName;
        op.SmsgInfo = rawKey;
        const head = await op.Encpw('arg2st', NormPW(password));
        rawKey.fill(0);
        return Encode64(head, '#');
    }

    // Import password-protected folder share token
    async ImportShareToken(tokenText, password) {
        try {
            if (!password || !tokenText) return null;
            const raw = Decode64(tokenText.trim(), '#');
            const op = new Opsec();
            op.View(raw);
            await op.Decpw(NormPW(password));
            if (!op.Smsg || op.SmsgInfo.length === 0) return null;
            const maskedKey = mask.XOR(op.SmsgInfo);
            op.SmsgInfo.fill(0);
            return { name: op.Smsg, key: maskedKey };
        } catch {
            return null;
        }
    }

    // ===== Session Storage =====
    // Encrypt session data and persist to browser storage
    async SaveSessionBytes(plainBytes) {
        if (!plainBytes || plainBytes.length === 0) {
            await this.ClearSessionBytes();
            return;
        }
        const kek = getOrGenerateSessionKek();
        const key = await importSessionKek(kek);
        const iv = new Uint8Array(12);
        crypto.getRandomValues(iv);

        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            plainBytes
        );

        const cipherBytes = new Uint8Array(cipherBuf);
        const payload = ToHex(iv) + ToHex(cipherBytes);
        iv.fill(0);
        sessionStorage.setItem(sessionVaultKey, payload);
    }

    // Retrieve and decrypt session data
    async LoadSessionBytes() {
        const payload = sessionStorage.getItem(sessionVaultKey);
        if (!payload || payload.length < 24) return null;

        try {
            const kek = getOrGenerateSessionKek();
            const iv = FromHex(payload.slice(0, 24));
            const cipher = FromHex(payload.slice(24));
            const key = await importSessionKek(kek);

            const buf = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                cipher
            );
            iv.fill(0);
            return new Uint8Array(buf);

        } catch (err) {
            console.warn('Failed to decrypt session data:', err);
            return null;
        }
    }

    // Clear session data and ephemeral key
    async ClearSessionBytes() {
        try {
            sessionStorage.removeItem(sessionVaultKey);
            sessionStorage.clear();
            window.name = '';
        } catch { }
    }
}

// Global adapter instance
export const Adapter = new AdapterService();
