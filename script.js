let currentResource = '';
let encryptedPasswords = {};

const resourceLinks = {
    'resource1': [
        { name: '百度网盘下载', url: 'https://pan.baidu.com/s/example1' },
        { name: '蓝奏云下载', url: 'https://lanzoux.com/example1' },
        { name: '天翼云下载', url: 'https://cloud.189.cn/example1' }
    ],
    'resource2': [
        { name: '百度网盘下载', url: 'https://pan.baidu.com/s/example2' },
        { name: '阿里云盘下载', url: 'https://aliyundrive.com/example2' }
    ],
    'resource3': [
        { name: '百度网盘下载', url: 'https://pan.baidu.com/s/example3' },
        { name: '夸克网盘下载', url: 'https://pan.quark.cn/example3' }
    ],
    'resource4': [
        { name: '百度网盘下载', url: 'https://pan.baidu.com/s/example4' },
        { name: '115网盘下载', url: 'https://115.com/example4' }
    ],
    'resource5': [
        { name: '百度网盘下载', url: 'https://pan.baidu.com/s/example5' },
        { name: '迅雷云盘下载', url: 'https://pan.xunlei.com/example5' }
    ]
};

// --- START: Corrected Hashing Functions ---

// SHA256 using Web Crypto API
async function sha256_crypto(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

/**
* MD5 (Message-Digest Algorithm)
* A JavaScript implementation of the RSA Data Security, Inc. MD5 Message-Digest Algorithm, as defined in RFC 1321.
* Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
* Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
* Distributed under the BSD License
* See http://pajhome.org.uk/crypt/md5 for more info.
*/
function md5_js(string) {
    function RotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }

    function AddUnsigned(lX, lY) {
        var lX4, lY4, lX8, lY8, lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) {
            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        }
        if (lX4 | lY4) {
            if (lResult & 0x40000000) {
                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            } else {
                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
            }
        } else {
            return (lResult ^ lX8 ^ lY8);
        }
    }

    function F(x, y, z) { return (x & y) | ((~x) & z); }
    function G(x, y, z) { return (x & z) | (y & (~z)); }
    function H(x, y, z) { return (x ^ y ^ z); }
    function I(x, y, z) { return (y ^ (x | (~z))); }

    function FF(a, b, c, d, x, s, t) {
        return AddUnsigned(RotateLeft(AddUnsigned(AddUnsigned(a, F(b, c, d)), AddUnsigned(x, t)), s), b);
    }

    function GG(a, b, c, d, x, s, t) {
        return AddUnsigned(RotateLeft(AddUnsigned(AddUnsigned(a, G(b, c, d)), AddUnsigned(x, t)), s), b);
    }

    function HH(a, b, c, d, x, s, t) {
        return AddUnsigned(RotateLeft(AddUnsigned(AddUnsigned(a, H(b, c, d)), AddUnsigned(x, t)), s), b);
    }

    function II(a, b, c, d, x, s, t) {
        return AddUnsigned(RotateLeft(AddUnsigned(AddUnsigned(a, I(b, c, d)), AddUnsigned(x, t)), s), b);
    }

    function ConvertToWordArray(string) {
        var lWordCount;
        var lMessageLength = string.length;
        var lNumberOfWords_temp1 = lMessageLength + 8;
        var lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        var lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        var lWordArray = Array(lNumberOfWords - 1);
        var lBytePosition = 0;
        var lByteCount = 0;
        while (lByteCount < lMessageLength) {
            lWordCount = (lByteCount - (lByteCount % 4)) / 4;
            lBytePosition = (lByteCount % 4) * 8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
        return lWordArray;
    }

    function WordToHex(lValue) {
        var WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            WordToHexValue_temp = "0" + lByte.toString(16);
            WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
        }
        return WordToHexValue;
    }

    function Utf8Encode(string) {
        string = string.replace(/\r\n/g, "\n");
        var utftext = "";
        for (var n = 0; n < string.length; n++) {
            var charcode = string.charCodeAt(n);
            if (charcode < 128) {
                utftext += String.fromCharCode(charcode);
            } else if ((charcode > 127) && (charcode < 2048)) {
                utftext += String.fromCharCode((charcode >> 6) | 192);
                utftext += String.fromCharCode((charcode & 63) | 128);
            } else {
                utftext += String.fromCharCode((charcode >> 12) | 224);
                utftext += String.fromCharCode(((charcode >> 6) & 63) | 128);
                utftext += String.fromCharCode((charcode & 63) | 128);
            }
        }
        return utftext;
    }

    var x = Array();
    var k, AA, BB, CC, DD, a, b, c, d;
    var S11 = 7, S12 = 12, S13 = 17, S14 = 22;
    var S21 = 5, S22 = 9, S23 = 14, S24 = 20;
    var S31 = 4, S32 = 11, S33 = 16, S34 = 23;
    var S41 = 6, S42 = 10, S43 = 15, S44 = 21;

    string = Utf8Encode(string);
    x = ConvertToWordArray(string);
    a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;

    for (k = 0; k < x.length; k += 16) {
        AA = a; BB = b; CC = c; DD = d;
        a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x02441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x04881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = AddUnsigned(a, AA);
        b = AddUnsigned(b, BB);
        c = AddUnsigned(c, CC);
        d = AddUnsigned(d, DD);
    }
    var temp = WordToHex(a) + WordToHex(b) + WordToHex(c) + WordToHex(d);
    return temp.toLowerCase();
}
// --- END: Corrected Hashing Functions ---

// Matching Python encryption algorithm's password verification
async function verifyPasswordWithPythonAlgorithm(inputPassword, encryptedData) {
    try {
        const data = JSON.parse(atob(encryptedData));
        const { hash: storedHash, salt, iterations } = data;
        
        let combined = inputPassword + salt;
        
        for (let i = 0; i < iterations; i++) {
            combined = await sha256_crypto(combined);
            combined = combined.split('').reverse().join('');
            if (i % 2 === 0) {
                combined = combined.toUpperCase();
            } else {
                combined = combined.toLowerCase();
            }
        }
        
        const finalHash = md5_js(combined).substring(0, 16);
        
        return finalHash === storedHash;
    } catch (e) {
        console.error('密码验证失败 (verifyPasswordWithPythonAlgorithm):', e);
        return false;
    }
}

async function loadPasswords() {
    try {
        const response = await fetch('./passwords.txt');
        if (!response.ok) {
            throw new Error('无法加载密码文件');
        }
        const text = await response.text();
        const lines = text.trim().split('\n');
        
        lines.forEach(line => {
            const [resourceId, encryptedData] = line.split('=');
            if (resourceId && encryptedData) {
                encryptedPasswords[resourceId.trim()] = encryptedData.trim();
            }
        });
        
        console.log('密码文件加载成功，共加载', Object.keys(encryptedPasswords).length, '个密码');
    } catch (error) {
        console.error('加载密码文件失败:', error);
        alert('密码文件加载失败，请检查文件是否存在');
    }
}

// Firebase配置和初始化
const firebaseConfig = {
    apiKey: "AIzaSyAOBvOeOWkRWWssJ0V0c-ge4j_YgNT2_Z4",
    authDomain: "resource-sharing-center.firebaseapp.com",
    projectId: "resource-sharing-center",
    storageBucket: "resource-sharing-center.firebasestorage.app",
    messagingSenderId: "846208459960",
    appId: "1:846208459960:web:b874dc71135c1217be004d",
    measurementId: "G-W606DJX5LW"
};

// 初始化Firebase
firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();

// 获取留言集合引用
const messagesRef = db.collection("messages");

// 实时监听留言变化
function setupMessagesListener() {
    messagesRef.orderBy("timestamp", "desc").onSnapshot(snapshot => {
        const messagesListEl = document.getElementById('messagesList');
        // 保留标题，清空其他内容
        const h3 = messagesListEl.querySelector('h3');
        messagesListEl.innerHTML = '';
        messagesListEl.appendChild(h3);
        
        if (snapshot.empty) {
            const noMessage = document.createElement('p');
            noMessage.textContent = '还没有留言，快来发表第一条吧！';
            messagesListEl.appendChild(noMessage);
            return;
        }
        
        snapshot.forEach(doc => {
            const msg = doc.data();
            const messageItem = document.createElement('div');
            messageItem.className = 'message-item';
            
            // 格式化时间
            const timestamp = msg.timestamp ? 
                new Date(msg.timestamp.toDate()).toLocaleString('zh-CN', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                }) : '未知时间';
            
            messageItem.innerHTML = `
                <div class="message-meta">
                    <span class="message-author">👤 ${msg.author}</span>
                    <span class="message-time">${timestamp}</span>
                </div>
                <div class="message-content">${msg.content}</div>
            `;
            
            // 如果有管理员回复
            if (msg.reply) {
                const adminReply = document.createElement('div');
                adminReply.className = 'admin-reply';
                adminReply.innerHTML = `
                    <span class="admin-tag">管理员回复</span>
                    <span class="reply-content">${msg.reply}</span>
                `;
                messageItem.appendChild(adminReply);
            }
            
            messagesListEl.appendChild(messageItem);
        });
    }, error => {
        console.error('留言监听失败:', error);
    });
}

function openPasswordModal(resourceId) {
    currentResource = resourceId;
    document.getElementById('passwordModal').style.display = 'block';
    document.getElementById('passwordInput').value = '';
    document.getElementById('passwordInput').focus();
    document.getElementById('errorMessage').style.display = 'none';
}

function closeModal() {
    document.getElementById('passwordModal').style.display = 'none';
    currentResource = '';
}

function closeSuccessPage() {
    document.getElementById('successPage').style.display = 'none';
    currentResource = '';
}

async function verifyPassword() {
    const inputPassword = document.getElementById('passwordInput').value;
    const encryptedData = encryptedPasswords[currentResource];
    
    if (!encryptedData) {
        document.getElementById('errorMessage').textContent = '密码配置错误';
        document.getElementById('errorMessage').style.display = 'block';
        return;
    }

    console.log('验证密码:', inputPassword, '对于资源:', currentResource);
    
    // Await the async verification function
    if (await verifyPasswordWithPythonAlgorithm(inputPassword, encryptedData)) {
        console.log('密码验证成功');
        showDownloadLinks();
    } else {
        console.log('密码验证失败');
        document.getElementById('errorMessage').textContent = '密码错误，请重新输入';
        document.getElementById('errorMessage').style.display = 'block';
        document.getElementById('passwordInput').value = '';
        document.getElementById('passwordInput').focus();
    }
}

function showDownloadLinks() {
    const links = resourceLinks[currentResource];
    const linksContainer = document.getElementById('downloadLinks');
    
    linksContainer.innerHTML = '';
    if (links && links.length > 0) {
        links.forEach(link => {
            const linkElement = document.createElement('a');
            linkElement.href = link.url;
            linkElement.className = 'download-link';
            linkElement.textContent = link.name;
            linkElement.target = '_blank';
            linksContainer.appendChild(linkElement);
        });
    } else {
         linksContainer.innerHTML = '<p>暂无此资源的下载链接配置。</p>';
    }
    document.getElementById('passwordModal').style.display = 'none';
    document.getElementById('successPage').style.display = 'block';
}

async function submitMessage() {
    const userName = document.getElementById('userName').value.trim();
    const userMessage = document.getElementById('userMessage').value.trim();

    if (!userName || !userMessage) {
        alert('请填写完整的昵称和留言内容！');
        return;
    }

    try {
        // 提交留言到Firebase
        await messagesRef.add({
            author: userName,
            content: userMessage,
            timestamp: firebase.firestore.FieldValue.serverTimestamp()
        });
        
        // 清空表单
        document.getElementById('userName').value = '';
        document.getElementById('userMessage').value = '';
        
        showSuccessNotification();
    } catch (error) {
        console.error('提交留言失败:', error);
        alert('提交留言失败，请重试！');
    }
}

function showSuccessNotification() {
    const notification = document.createElement('div');
    notification.className = 'success-notification';
    notification.innerHTML = '✅ 留言提交成功！我们会尽快处理您的需求。';
    
    const messageForm = document.querySelector('.message-form');
    messageForm.parentNode.insertBefore(notification, messageForm);

    notification.style.display = 'block';

    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}

document.addEventListener('DOMContentLoaded', function() {
    loadPasswords();
    setupMessagesListener();
});

document.addEventListener('keydown', async function(event) {
    if (document.getElementById('passwordModal').style.display === 'block') {
        if (event.key === 'Enter') {
            await verifyPassword();
        } else if (event.key === 'Escape') {
            closeModal();
        }
    } else if (document.getElementById('successPage').style.display === 'block') {
        if (event.key === 'Escape') {
            closeSuccessPage();
        }
    }
});

window.onclick = function(event) {
    const passwordModal = document.getElementById('passwordModal');
    const successModal = document.getElementById('successPage');
    
    if (event.target === passwordModal) {
        closeModal();
    } else if (event.target === successModal) {
        closeSuccessPage();
    }
}

document.getElementById('passwordInput').addEventListener('input', function(e) {
    // 允许任意字符输入
});
