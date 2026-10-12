const SHIFT_SEQUENCE = [1, 4, 0, 2, 1, 4];
const SECRET_KEY = "1402"; // Chave oculta e fixa internamente

function codificarBase64(str) {
    const utf8Bytes = new TextEncoder().encode(str);
    let binaryString = '';
    for (let i = 0; i < utf8Bytes.length; i++) {
        binaryString += String.fromCharCode(utf8Bytes[i]);
    }
    return btoa(binaryString);
}

function decodificarBase64(base64Str) {
    const binaryString = atob(base64Str);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}

function aplicarDeslocamentos(bytes) {
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        const shift = SHIFT_SEQUENCE[i % SHIFT_SEQUENCE.length];
        result[i] = (bytes[i] + shift) % 256;
    }
    return result;
}

function reverterDeslocamentos(bytes) {
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        const shift = SHIFT_SEQUENCE[i % SHIFT_SEQUENCE.length];
        result[i] = (bytes[i] - shift + 256) % 256;
    }
    return result;
}

function gerarOrdemPermutacao(blockSize, chaveStr) {
    let seed = 0;
    for (let i = 0; i < chaveStr.length; i++) {
        seed = (seed * 31 + chaveStr.charCodeAt(i)) % 1000000;
    }
    
    const indices = Array.from({length: blockSize}, (_, i) => i);
    for (let i = blockSize - 1; i > 0; i--) {
        seed = (seed * 9301 + 49297) % 233280;
        const j = Math.floor((seed / 233280) * (i + 1));
        [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    return indices;
}

function aplicarPermutacaoBlocos(bytes, chaveStr) {
    const blockSize = 8;
    const numBlocks = Math.ceil(bytes.length / blockSize);
    const result = new Uint8Array(bytes.length);
    const permutation = gerarOrdemPermutacao(blockSize, chaveStr);

    for (let b = 0; b < numBlocks; b++) {
        const start = b * blockSize;
        const currentBlockSize = Math.min(blockSize, bytes.length - start);
        
        for (let i = 0; i < currentBlockSize; i++) {
            const targetIdx = permutation[i] < currentBlockSize ? permutation[i] : i;
            result[start + i] = bytes[start + targetIdx];
        }
    }
    return result;
}

function reverterPermutacaoBlocos(bytes, chaveStr) {
    const blockSize = 8;
    const numBlocks = Math.ceil(bytes.length / blockSize);
    const result = new Uint8Array(bytes.length);
    const permutation = gerarOrdemPermutacao(blockSize, chaveStr);
    
    const inversePermutation = new Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        const targetIdx = permutation[i] < blockSize ? permutation[i] : i;
        inversePermutation[targetIdx] = i;
    }

    for (let b = 0; b < numBlocks; b++) {
        const start = b * blockSize;
        const currentBlockSize = Math.min(blockSize, bytes.length - start);
        
        for (let i = 0; i < currentBlockSize; i++) {
            const origIdx = inversePermutation[i] < currentBlockSize ? inversePermutation[i] : i;
            result[start + i] = bytes[start + origIdx];
        }
    }
    return result;
}

function cifrar(texto, chave) {
    if (!texto) throw new Error("O texto de entrada esta vazio.");
    
    const base64Intermediario = codificarBase64(texto);
    const bytesIntermediarios = new TextEncoder().encode(base64Intermediario);
    const bytesDeslocados = aplicarDeslocamentos(bytesIntermediarios);
    const bytesPermutados = aplicarPermutacaoBlocos(bytesDeslocados, chave);
    
    let binaryString = '';
    for (let i = 0; i < bytesPermutados.length; i++) {
        binaryString += String.fromCharCode(bytesPermutados[i]);
    }
    return btoa(binaryString);
}

function decifrar(textoCifrado, chave) {
    if (!textoCifrado) throw new Error("O texto cifrado esta vazio.");
    
    const binaryString = atob(textoCifrado.trim());
    const bytesPermutados = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytesPermutados[i] = binaryString.charCodeAt(i);
    }

    const bytesDeslocados = reverterPermutacaoBlocos(bytesPermutados, chave);
    const bytesIntermediarios = reverterDeslocamentos(bytesDeslocados);
    
    const base64Intermediario = new TextDecoder().decode(bytesIntermediarios);
    return decodificarBase64(base64Intermediario);
}

function mostrarStatus(mensagem, tipo) {
    const box = document.getElementById('statusBox');
    box.className = `status-box ${tipo}`;
    box.textContent = mensagem;
}

function limparStatus() {
    const box = document.getElementById('statusBox');
    box.className = 'status-box';
    box.textContent = '';
}

document.getElementById('encryptBtn').addEventListener('click', () => {
    try {
        limparStatus();
        const texto = document.getElementById('inputText').value;
        const resultado = cifrar(texto, SECRET_KEY);
        document.getElementById('outputText').value = resultado;
        mostrarStatus('Texto cifrado com sucesso.', 'success');
    } catch (err) {
        mostrarStatus('Erro ao cifrar: ' + err.message, 'error');
    }
});

document.getElementById('decryptBtn').addEventListener('click', () => {
    try {
        limparStatus();
        const textoCifrado = document.getElementById('inputText').value;
        const resultado = decifrar(textoCifrado, SECRET_KEY);
        document.getElementById('outputText').value = resultado;
        mostrarStatus('Texto decifrado com sucesso.', 'success');
    } catch (err) {
        mostrarStatus('Erro ao decifrar. Verifique o texto cifrado.', 'error');
    }
});

const exemplos = [
    "miopia"
];

const examplesList = document.getElementById('examplesList');
exemplos.forEach(ex => {
    const chip = document.createElement('div');
    chip.className = 'example-chip';
    chip.textContent = ex;
    chip.addEventListener('click', () => {
        document.getElementById('inputText').value = ex;
        limparStatus();
    });
    examplesList.appendChild(chip);
});
