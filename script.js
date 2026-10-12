/* =========================================================
   Miopia Cipher
   A chave é fixa e vive só aqui. Não existe campo para trocá-la.
   ========================================================= */

const SEGREDO = "1402";
const TEMPERO = "miopia/névoa/v3";
const ITERACOES = 250000;
const TAM_SAL = 16;
const TAM_IV = 12;
const TAM_TAG = 16;
const BLOCO = 64;
const LIMITE_CARACTERES = 200000;
const ALFABETO = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

class ErroCifra extends Error {
    constructor(mensagem) { super(mensagem); this.name = "ErroCifra"; }
}

/* ---------- Representação em texto ---------- */

function paraBase32(bytes) {
    let bits = 0, valor = 0, saida = "";
    for (const b of bytes) {
        valor = (valor << 8) | b;
        bits += 8;
        while (bits >= 5) {
            saida += ALFABETO[(valor >>> (bits - 5)) & 31];
            bits -= 5;
        }
        valor &= (1 << bits) - 1;
    }
    if (bits > 0) saida += ALFABETO[(valor << (5 - bits)) & 31];
    return saida;
}

function deBase32(texto) {
    const limpo = texto.toUpperCase()
        .replace(/[\s-]/g, "")
        .replace(/O/g, "0")
        .replace(/[IL]/g, "1");
    if (!limpo) throw new ErroCifra("Cole um texto cifrado antes de decifrar.");

    const bytes = [];
    let bits = 0, valor = 0;
    for (const c of limpo) {
        const v = ALFABETO.indexOf(c);
        if (v < 0) throw new ErroCifra("Este texto não parece ter sido cifrado aqui. Confira se foi copiado por inteiro.");
        valor = (valor << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bytes.push((valor >>> (bits - 8)) & 255);
            bits -= 8;
            valor &= (1 << bits) - 1;
        }
    }
    return Uint8Array.from(bytes);
}

function agrupar(s) {
    return s.match(/.{1,5}/g).join(" ");
}

/* ---------- Utilidades ---------- */

function aleatorio(n) {
    const b = new Uint8Array(n);
    globalThis.crypto.getRandomValues(b);
    return b;
}

function unicodeValido(texto) {
    if (typeof texto.isWellFormed === "function") return texto.isWellFormed();
    return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(texto);
}

function garantirCripto() {
    const c = globalThis.crypto;
    if (!c || !c.subtle || !c.getRandomValues) {
        throw new ErroCifra("Este navegador bloqueou a criptografia. Abra o arquivo direto no computador ou por https, em um navegador atualizado.");
    }
}

async function derivarChave(sal) {
    const base = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(SEGREDO + "|" + TEMPERO),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: sal, iterations: ITERACOES, hash: "SHA-256" },
        base,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/* ---------- Cifrar e decifrar ---------- */

async function cifrar(texto) {
    garantirCripto();
    if (!texto) throw new ErroCifra("Escreva algum texto antes de cifrar.");
    if (!unicodeValido(texto)) throw new ErroCifra("O texto tem caracteres Unicode inválidos.");
    if (texto.length > LIMITE_CARACTERES) throw new ErroCifra(`O texto passa de ${LIMITE_CARACTERES} caracteres.`);

    const dados = new TextEncoder().encode(texto);
    const total = Math.ceil((4 + dados.length) / BLOCO) * BLOCO;
    const quadro = new Uint8Array(total);
    new DataView(quadro.buffer).setUint32(0, dados.length);
    quadro.set(dados, 4);
    for (let i = 4 + dados.length; i < total; i += 1024) {
        quadro.set(aleatorio(Math.min(1024, total - i)), i);
    }

    const sal = aleatorio(TAM_SAL);
    const iv = aleatorio(TAM_IV);
    const chave = await derivarChave(sal);
    const cifrado = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, chave, quadro));

    const pacote = new Uint8Array(TAM_SAL + TAM_IV + cifrado.length);
    pacote.set(sal, 0);
    pacote.set(iv, TAM_SAL);
    pacote.set(cifrado, TAM_SAL + TAM_IV);
    return agrupar(paraBase32(pacote));
}

async function decifrar(textoCifrado) {
    garantirCripto();
    const pacote = deBase32(textoCifrado || "");
    const falha = new ErroCifra("Não foi possível decifrar. O texto foi alterado, está incompleto ou não veio daqui.");

    if (pacote.length < TAM_SAL + TAM_IV + TAM_TAG + BLOCO) throw falha;

    const sal = pacote.slice(0, TAM_SAL);
    const iv = pacote.slice(TAM_SAL, TAM_SAL + TAM_IV);
    const cifrado = pacote.slice(TAM_SAL + TAM_IV);

    let quadro;
    try {
        const chave = await derivarChave(sal);
        quadro = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, chave, cifrado));
    } catch (_) {
        throw falha;
    }

    const tamanho = new DataView(quadro.buffer).getUint32(0);
    if (tamanho > quadro.length - 4) throw falha;
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(quadro.subarray(4, 4 + tamanho));
    } catch (_) {
        throw falha;
    }
}

/* ===== interface ===== */

const $ = id => document.getElementById(id);
const entrada = $("inputText");
const saida = $("outputText");
const aviso = $("statusBox");
const hero = $("hero");
const btnCifrar = $("encryptBtn");
const btnDecifrar = $("decryptBtn");
const reduzMovimento = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const GLIFOS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ#%&*+=<>";

let resultado = "";
let temporizador = null;
let quadro = null;
let ocupado = false;

function mostrar(mensagem, tipo) {
    clearTimeout(temporizador);
    aviso.textContent = mensagem;
    aviso.className = "status show " + tipo;
    if (tipo === "ok") temporizador = setTimeout(esconder, 3500);
}

function esconder() {
    clearTimeout(temporizador);
    aviso.className = "status";
}

function contar() {
    $("inCount").textContent = [...entrada.value].length;
    $("outCount").textContent = [...(resultado || saida.value)].length;
}

function travar(sim) {
    ocupado = sim;
    btnCifrar.disabled = sim;
    btnDecifrar.disabled = sim;
}

function revelar(texto) {
    resultado = texto;
    cancelAnimationFrame(quadro);
    const chars = [...texto];
    if (reduzMovimento || chars.length > 1800) {
        saida.value = texto;
        contar();
        return;
    }
    const inicio = performance.now();
    const duracao = Math.min(1200, 450 + chars.length * 5);
    const passo = agora => {
        const p = Math.min(1, (agora - inicio) / duracao);
        let s = "";
        for (let i = 0; i < chars.length; i++) {
            const c = chars[i];
            const pronto = p >= 0.12 + 0.88 * (i / chars.length);
            s += (pronto || /\s/.test(c)) ? c : GLIFOS[Math.floor(Math.random() * GLIFOS.length)];
        }
        saida.value = s;
        if (p < 1) quadro = requestAnimationFrame(passo);
        else saida.value = texto;
        contar();
    };
    quadro = requestAnimationFrame(passo);
}

async function executar(operacao) {
    if (ocupado) return;
    esconder();
    hero.classList.remove("focused");
    travar(true);
    mostrar("Processando", "wait");
    try {
        const texto = operacao === "cifrar"
            ? await cifrar(entrada.value)
            : await decifrar(entrada.value);
        revelar(texto);
        hero.classList.add("focused");
        mostrar(operacao === "cifrar" ? "Texto cifrado." : "Texto decifrado.", "ok");
    } catch (erro) {
        cancelAnimationFrame(quadro);
        resultado = "";
        saida.value = "";
        contar();
        mostrar(erro instanceof ErroCifra ? erro.message : "Algo deu errado. Tente de novo.", "err");
    } finally {
        travar(false);
    }
}

async function copiar(texto) {
    try {
        await navigator.clipboard.writeText(texto);
    } catch (_) {
        const aux = document.createElement("textarea");
        aux.value = texto;
        aux.style.position = "fixed";
        aux.style.opacity = "0";
        document.body.appendChild(aux);
        aux.select();
        document.execCommand("copy");
        aux.remove();
    }
}

/* ---------- Eventos ---------- */

btnCifrar.addEventListener("click", () => executar("cifrar"));
btnDecifrar.addEventListener("click", () => executar("decifrar"));

$("copyBtn").addEventListener("click", async () => {
    if (!resultado) return mostrar("Ainda não há resultado para copiar.", "err");
    await copiar(resultado);
    mostrar("Resultado copiado.", "ok");
});

$("moveBtn").addEventListener("click", () => {
    if (!resultado) return mostrar("Ainda não há resultado para mover.", "err");
    entrada.value = resultado;
    resultado = "";
    saida.value = "";
    hero.classList.remove("focused");
    esconder();
    contar();
    entrada.focus();
});

$("clearBtn").addEventListener("click", () => {
    cancelAnimationFrame(quadro);
    entrada.value = "";
    saida.value = "";
    resultado = "";
    hero.classList.remove("focused");
    esconder();
    contar();
    entrada.focus();
});

entrada.addEventListener("input", contar);
entrada.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        executar("cifrar");
    }
});

["miopia", "Olá, mundo!"].forEach(exemplo => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "sample";
    b.textContent = exemplo;
    b.addEventListener("click", () => {
        entrada.value = exemplo;
        esconder();
        contar();
    });
    $("samplesList").appendChild(b);
});

window.addEventListener("pointermove", e => {
    document.documentElement.style.setProperty("--mx", e.clientX + "px");
    document.documentElement.style.setProperty("--my", e.clientY + "px");
}, { passive: true });

contar();
