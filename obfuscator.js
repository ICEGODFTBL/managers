// ICE Obfuscator v1.0
// Usage: node obfuscator.js <input.lua> <output.lua>
// Or pipe: echo "print('hi')" | node obfuscator.js

'use strict';
const fs = require('fs');
const crypto = require('crypto');

// ─── UTILS ────────────────────────────────────────────────────────────────────

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randName(len = rand(6, 10)) {
    const a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
    const all = a + '0123456789';
    let r = a[rand(0, a.length - 1)];
    for (let i = 1; i < len; i++) r += all[rand(0, all.length - 1)];
    return r;
}
function genKey(n = 32) {
    return Array.from(crypto.randomBytes(n));
}
function xorBuf(str, key) {
    const out = [];
    for (let i = 0; i < str.length; i++)
        out.push((str.charCodeAt(i) ^ key[i % key.length]) & 0xFF);
    return out;
}
function escStr(bytes) {
    return '"' + bytes.map(b => '\\' + b.toString(8).padStart(3, '0')).join('') + '"';
}
function keyStr(key) { return '{' + key.join(',') + '}'; }

// LCG key derivation (same logic as the bot's known method)
function lcgDeriveKey(seed, baseKey) {
    let s = seed >>> 0;
    return baseKey.map((b, i) => {
        s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
        return (b ^ ((s >> (i % 24)) & 0xFF)) & 0xFF;
    });
}

// ─── TOKENIZER ────────────────────────────────────────────────────────────────

const KEYWORDS = new Set([
    'and','break','do','else','elseif','end','false','for','function',
    'goto','if','in','local','nil','not','or','repeat','return',
    'then','true','until','while'
]);

function tokenize(src) {
    const tokens = [];
    let i = 0;
    const len = src.length;
    while (i < len) {
        // whitespace
        if (/\s/.test(src[i])) { i++; continue; }
        // long string / comment
        if (src[i] === '-' && src[i+1] === '-') {
            if (src[i+2] === '[') {
                let eq = 0; let j = i+3;
                while (src[j] === '=') { eq++; j++; }
                if (src[j] === '[') {
                    const close = ']' + '='.repeat(eq) + ']';
                    const end = src.indexOf(close, j+1);
                    i = end === -1 ? len : end + close.length;
                } else { const nl = src.indexOf('\n', i); i = nl === -1 ? len : nl+1; }
            } else { const nl = src.indexOf('\n', i); i = nl === -1 ? len : nl+1; }
            continue;
        }
        // long string literal
        if (src[i] === '[') {
            let eq = 0; let j = i+1;
            while (src[j] === '=') { eq++; j++; }
            if (src[j] === '[') {
                const close = ']' + '='.repeat(eq) + ']';
                const end = src.indexOf(close, j+1);
                const raw = src.slice(j+1, end === -1 ? len : end);
                tokens.push({ type: 'STRING', value: raw });
                i = end === -1 ? len : end + close.length;
                continue;
            }
        }
        // string
        if (src[i] === '"' || src[i] === "'") {
            const q = src[i]; let s = ''; let j = i+1;
            while (j < len && src[j] !== q) {
                if (src[j] === '\\') {
                    const e = src[j+1];
                    if (e === 'n') s += '\n';
                    else if (e === 't') s += '\t';
                    else if (e === 'r') s += '\r';
                    else if (/\d/.test(e)) {
                        let ns = ''; let k = j+1;
                        while (k < j+4 && /\d/.test(src[k])) { ns += src[k]; k++; }
                        s += String.fromCharCode(parseInt(ns));
                        j = k - 1;
                    } else s += e;
                    j += 2;
                } else { s += src[j]; j++; }
            }
            tokens.push({ type: 'STRING', value: s });
            i = j+1; continue;
        }
        // number
        const nm = src.slice(i).match(/^0[xX][0-9a-fA-F]+|^\d+\.?\d*(?:[eE][+-]?\d+)?|^\.\d+/);
        if (nm) {
            tokens.push({ type: 'NUMBER', value: nm[0] });
            i += nm[0].length; continue;
        }
        // ident / keyword
        const id = src.slice(i).match(/^[a-zA-Z_]\w*/);
        if (id) {
            const v = id[0];
            tokens.push({ type: KEYWORDS.has(v) ? 'KEYWORD' : 'IDENT', value: v });
            i += v.length; continue;
        }
        // symbols (longest match)
        const syms = ['...','..','==','~=','<=','>=','<<','>>','//','::',
                      '+','-','*','/','%','^','#','&','~','|','<','>',
                      '=','(',')','{','}','[',']',';',':',',','.'];
        let matched = false;
        for (const s of syms) {
            if (src.startsWith(s, i)) {
                tokens.push({ type: 'SYM', value: s });
                i += s.length; matched = true; break;
            }
        }
        if (!matched) i++;
    }
    return tokens;
}

// ─── OPCODES ──────────────────────────────────────────────────────────────────

const OP = {
    LCONST:1, LVAR:2, SVAR:3, LGLOBAL:4, SGLOBAL:5,
    CALL:6, RET:7, ADD:8, SUB:9, MUL:10, DIV:11, MOD:12,
    POW:13, CAT:14, EQ:15, NE:16, LT:17, LE:18, GT:19, GE:20,
    AND:21, OR:22, NOT:23, NEG:24, LEN:25, JMP:26, JIF:27, JIFN:28,
    NTBL:29, GTBL:30, STBL:31, NIL:32, TRUE:33, FALSE:34,
    POP:35, DUP:36, CLOSE:37, NOP:47,
};

// ─── COMPILER ─────────────────────────────────────────────────────────────────

function compile(tokens) {
    const bc = [];
    const consts = [];
    const cmap = {};
    const loops = [];
    let pos = 0;

    function addC(v, t) {
        const k = t + ':' + String(v);
        if (cmap[k] !== undefined) return cmap[k];
        consts.push({ t, v });
        return (cmap[k] = consts.length);
    }
    function emit(op, ...args) { bc.push({ op, a: args }); return bc.length; }
    function patch(idx, tgt) { if (bc[idx-1]) bc[idx-1].a[0] = tgt; }
    function cur() { return tokens[pos]; }
    function peek(n=0) { return tokens[pos+n]; }
    function adv() { return tokens[pos++]; }
    function chk(t,v) { const c=cur(); return c && c.type===t && (!v||c.value===v); }
    function eat(t,v) { if (chk(t,v)) return adv(); }

    let compilePrimary, compileUnary, compileArith, compileCmp, compileExpr, compileStmt;

    compilePrimary = function() {
        const t = cur();
        if (!t) return;
        if (t.type==='NUMBER') { adv(); emit(OP.LCONST, addC(parseFloat(t.value),'n')); return; }
        if (t.type==='STRING') { adv(); emit(OP.LCONST, addC(t.value,'s')); return; }
        if (t.type==='KEYWORD') {
            if (t.value==='nil') { adv(); emit(OP.NIL); return; }
            if (t.value==='true') { adv(); emit(OP.TRUE); return; }
            if (t.value==='false') { adv(); emit(OP.FALSE); return; }
            if (t.value==='function') {
                adv(); eat('SYM','(');
                while (!chk('SYM',')') && cur()) adv();
                eat('SYM',')');
                let d=1;
                while (d>0 && cur()) {
                    if (['function','if','do','while','for'].includes(cur().value)) d++;
                    else if (cur().value==='end') d--;
                    adv();
                }
                emit(OP.NIL); return;
            }
        }
        if (t.type==='IDENT') {
            adv();
            emit(OP.LGLOBAL, addC(t.value,'s'));
            while (cur()) {
                if (chk('SYM','(')) {
                    adv(); let argc=0;
                    while (!chk('SYM',')') && cur()) { compileExpr(); argc++; if (!eat('SYM',',')) break; }
                    eat('SYM',')'); emit(OP.CALL, argc);
                } else if (chk('SYM','.')) {
                    adv(); const f=adv();
                    if (f) { emit(OP.LCONST, addC(f.value,'s')); emit(OP.GTBL); }
                } else if (chk('SYM','[')) {
                    adv(); compileExpr(); eat('SYM',']'); emit(OP.GTBL);
                } else if (chk('SYM',':')) {
                    adv(); const m=adv();
                    if (m && chk('SYM','(')) {
                        emit(OP.DUP); emit(OP.LCONST, addC(m.value,'s')); emit(OP.GTBL);
                        adv(); let argc=1;
                        while (!chk('SYM',')') && cur()) { compileExpr(); argc++; if (!eat('SYM',',')) break; }
                        eat('SYM',')'); emit(OP.CALL, argc);
                    }
                } else break;
            }
            return;
        }
        if (chk('SYM','(')) {
            adv(); compileExpr(); eat('SYM',')');
            while (chk('SYM','(') || chk('SYM','.') || chk('SYM','[')) {
                if (chk('SYM','(')) {
                    adv(); let argc=0;
                    while (!chk('SYM',')') && cur()) { compileExpr(); argc++; if (!eat('SYM',',')) break; }
                    eat('SYM',')'); emit(OP.CALL, argc);
                } else if (chk('SYM','.')) {
                    adv(); const f=adv();
                    if (f) { emit(OP.LCONST, addC(f.value,'s')); emit(OP.GTBL); }
                } else if (chk('SYM','[')) {
                    adv(); compileExpr(); eat('SYM',']'); emit(OP.GTBL);
                }
            }
            return;
        }
        if (chk('SYM','{')) {
            adv(); emit(OP.NTBL); let idx=1;
            while (!chk('SYM','}') && cur()) {
                if (chk('SYM','[')) {
                    adv(); emit(OP.DUP); compileExpr(); eat('SYM',']'); eat('SYM','='); compileExpr(); emit(OP.STBL);
                } else if (peek(1) && peek(1).type==='SYM' && peek(1).value==='=') {
                    const k=adv(); adv(); emit(OP.DUP); emit(OP.LCONST, addC(k.value,'s')); compileExpr(); emit(OP.STBL);
                } else {
                    emit(OP.DUP); emit(OP.LCONST, addC(idx,'n')); compileExpr(); emit(OP.STBL); idx++;
                }
                eat('SYM',','); eat('SYM',';');
            }
            eat('SYM','}'); return;
        }
    };

    compileUnary = function() {
        if (chk('KEYWORD','not')) { adv(); compileUnary(); emit(OP.NOT); }
        else if (chk('SYM','-')) { adv(); compileUnary(); emit(OP.NEG); }
        else if (chk('SYM','#')) { adv(); compileUnary(); emit(OP.LEN); }
        else compilePrimary();
    };

    const mulOps = {'*':OP.MUL,'/':OP.DIV,'%':OP.MOD,'^':OP.POW,'//':OP.DIV};
    const addOps = {'+':OP.ADD,'-':OP.SUB,'..':OP.CAT};
    const cmpOps = {'==':OP.EQ,'~=':OP.NE,'<':OP.LT,'<=':OP.LE,'>':OP.GT,'>=':OP.GE};

    compileArith = function() {
        compileUnary();
        while (cur() && cur().type==='SYM' && mulOps[cur().value]) { const op=adv().value; compileUnary(); emit(mulOps[op]); }
        while (cur() && cur().type==='SYM' && addOps[cur().value]) {
            const op=adv().value; compileUnary();
            while (cur() && cur().type==='SYM' && mulOps[cur().value]) { const op2=adv().value; compileUnary(); emit(mulOps[op2]); }
            emit(addOps[op]);
        }
    };

    compileCmp = function() {
        compileArith();
        while (cur() && cur().type==='SYM' && cmpOps[cur().value]) { const op=adv().value; compileArith(); emit(cmpOps[op]); }
    };

    compileExpr = function() {
        compileCmp();
        while (cur() && cur().type==='KEYWORD') {
            if (cur().value==='and') { adv(); compileCmp(); emit(OP.AND); }
            else if (cur().value==='or') { adv(); compileCmp(); emit(OP.OR); }
            else break;
        }
    };

    compileStmt = function() {
        const t = cur();
        if (!t) return false;

        if (t.type==='KEYWORD') {
            if (t.value==='local') {
                adv();
                if (chk('KEYWORD','function')) {
                    adv(); const name=adv();
                    eat('SYM','(');
                    while (!chk('SYM',')') && cur()) adv();
                    eat('SYM',')');
                    let d=1;
                    while (d>0 && cur()) {
                        if (['function','if','do','while','for','repeat'].includes(cur().value)) d++;
                        else if (cur().value==='end') d--;
                        adv();
                    }
                    emit(OP.NIL); emit(OP.SVAR, addC(name.value,'s'));
                } else {
                    const vars=[];
                    do { const v=adv(); if (v && v.type==='IDENT') vars.push(v.value); } while (eat('SYM',','));
                    if (eat('SYM','=')) {
                        for (let i=0; i<vars.length; i++) { if (i>0) eat('SYM',','); compileExpr(); emit(OP.SVAR, addC(vars[i],'s')); }
                    } else {
                        for (const v of vars) { emit(OP.NIL); emit(OP.SVAR, addC(v,'s')); }
                    }
                }
            } else if (t.value==='if') {
                adv(); const endJmps=[];
                compileExpr(); eat('KEYWORD','then');
                const jf=emit(OP.JIFN,0);
                while (!['else','elseif','end'].includes(cur()?.value) && cur()) { if (!compileStmt()) break; }
                endJmps.push(emit(OP.JMP,0)); patch(jf, bc.length+1);
                while (chk('KEYWORD','elseif')) {
                    adv(); compileExpr(); eat('KEYWORD','then');
                    const jf2=emit(OP.JIFN,0);
                    while (!['else','elseif','end'].includes(cur()?.value) && cur()) { if (!compileStmt()) break; }
                    endJmps.push(emit(OP.JMP,0)); patch(jf2, bc.length+1);
                }
                if (eat('KEYWORD','else')) { while (!chk('KEYWORD','end') && cur()) { if (!compileStmt()) break; } }
                eat('KEYWORD','end');
                for (const j of endJmps) patch(j, bc.length+1);
            } else if (t.value==='while') {
                adv(); const ls=bc.length+1; loops.push({start:ls,breaks:[]});
                compileExpr(); eat('KEYWORD','do');
                const jf=emit(OP.JIFN,0);
                while (!chk('KEYWORD','end') && cur()) { if (!compileStmt()) break; }
                emit(OP.JMP,ls); eat('KEYWORD','end'); patch(jf, bc.length+1);
                const lp=loops.pop(); for (const b of lp.breaks) patch(b, bc.length+1);
            } else if (t.value==='for') {
                adv(); const v=adv();
                if (eat('SYM','=')) {
                    const vi=addC(v.value,'s'); compileExpr(); emit(OP.SVAR,vi);
                    eat('SYM',','); compileExpr();
                    const li=addC('__lim'+rand(1e4,9e4),'s'); emit(OP.SVAR,li);
                    const si=addC('__stp'+rand(1e4,9e4),'s');
                    if (eat('SYM',',')) compileExpr(); else emit(OP.LCONST,addC(1,'n'));
                    emit(OP.SVAR,si); eat('KEYWORD','do');
                    const ls=bc.length+1; loops.push({start:ls,breaks:[]});
                    emit(OP.LVAR,vi); emit(OP.LVAR,li); emit(OP.LE);
                    const jf=emit(OP.JIFN,0);
                    while (!chk('KEYWORD','end') && cur()) { if (!compileStmt()) break; }
                    emit(OP.LVAR,vi); emit(OP.LVAR,si); emit(OP.ADD); emit(OP.SVAR,vi);
                    emit(OP.JMP,ls); eat('KEYWORD','end'); patch(jf, bc.length+1);
                    const lp=loops.pop(); for (const b of lp.breaks) patch(b, bc.length+1);
                } else {
                    while (!chk('KEYWORD','do') && cur()) adv();
                    eat('KEYWORD','do'); let d=1;
                    while (d>0 && cur()) {
                        if (['for','while','if','function','do'].includes(cur().value)) d++;
                        else if (cur().value==='end') d--;
                        if (d>0) adv(); else adv();
                    }
                }
            } else if (t.value==='repeat') {
                adv(); const ls=bc.length+1; loops.push({start:ls,breaks:[]});
                while (!chk('KEYWORD','until') && cur()) { if (!compileStmt()) break; }
                eat('KEYWORD','until'); compileExpr(); emit(OP.JIFN,ls);
                const lp=loops.pop(); for (const b of lp.breaks) patch(b, bc.length+1);
            } else if (t.value==='return') {
                adv(); let rc=0;
                if (cur() && !['end','else','elseif','until'].includes(cur().value)) {
                    do { compileExpr(); rc++; } while (eat('SYM',','));
                }
                emit(OP.RET, rc);
            } else if (t.value==='break') {
                adv();
                if (loops.length) { const bi=emit(OP.JMP,0); loops[loops.length-1].breaks.push(bi); }
            } else if (t.value==='do') {
                adv(); while (!chk('KEYWORD','end') && cur()) { if (!compileStmt()) break; } eat('KEYWORD','end');
            } else return false;
        } else if (t.type==='IDENT') {
            const name=t.value; adv();
            const accs=[];
            while (chk('SYM','.') || chk('SYM','[')) {
                if (eat('SYM','.')) { const f=adv(); if (f) accs.push({t:'f',v:f.value}); }
                else if (eat('SYM','[')) { accs.push({t:'i'}); compileExpr(); eat('SYM',']'); }
            }
            if (eat('SYM','=')) {
                const idx=addC(name,'s');
                if (!accs.length) { compileExpr(); emit(OP.SVAR,idx); }
                else {
                    emit(OP.LGLOBAL,idx);
                    for (let i=0;i<accs.length-1;i++) { if (accs[i].t==='f') { emit(OP.LCONST,addC(accs[i].v,'s')); emit(OP.GTBL); } }
                    const last=accs[accs.length-1];
                    if (last.t==='f') emit(OP.LCONST,addC(last.v,'s'));
                    compileExpr(); emit(OP.STBL);
                }
            } else if (chk('SYM','(')) {
                emit(OP.LGLOBAL,addC(name,'s'));
                for (const a of accs) { if (a.t==='f') { emit(OP.LCONST,addC(a.v,'s')); emit(OP.GTBL); } }
                adv(); let argc=0;
                while (!chk('SYM',')') && cur()) { compileExpr(); argc++; if (!eat('SYM',',')) break; }
                eat('SYM',')'); emit(OP.CALL,argc); emit(OP.POP);
            } else if (chk('SYM',':')) {
                emit(OP.LGLOBAL,addC(name,'s'));
                for (const a of accs) { if (a.t==='f') { emit(OP.LCONST,addC(a.v,'s')); emit(OP.GTBL); } }
                adv(); const m=adv();
                if (m && chk('SYM','(')) {
                    emit(OP.DUP); emit(OP.LCONST,addC(m.value,'s')); emit(OP.GTBL);
                    adv(); let argc=1;
                    while (!chk('SYM',')') && cur()) { compileExpr(); argc++; if (!eat('SYM',',')) break; }
                    eat('SYM',')'); emit(OP.CALL,argc); emit(OP.POP);
                }
            } else if (eat('SYM',',')) {
                const vars=[name];
                do { const v=adv(); if (v && v.type==='IDENT') vars.push(v.value); } while (eat('SYM',','));
                eat('SYM','=');
                let ec=0;
                do { compileExpr(); ec++; } while (eat('SYM',','));
                while (ec < vars.length) { emit(OP.NIL); ec++; }
                for (let i=vars.length-1; i>=0; i--) emit(OP.SVAR,addC(vars[i],'s'));
            } else return false;
        } else return false;
        return true;
    };

    while (pos < tokens.length) { if (!compileStmt()) pos++; }
    emit(OP.RET, 0);
    return { bc, consts };
}

// ─── ENCRYPTION ───────────────────────────────────────────────────────────────

function encryptConsts(consts, key) {
    for (const c of consts) {
        if (c.t === 's') {
            // Layer 1: XOR
            let bytes = xorBuf(c.v, key);
            // Layer 2: rotate +137
            bytes = bytes.map(b => (b + 137) & 0xFF);
            // Layer 3: XOR with derived key
            const dk = lcgDeriveKey(0xDEADBEEF, key);
            bytes = bytes.map((b,i) => b ^ (dk[i % dk.length] & 0xFF));
            c.enc = bytes;
        }
    }
}

// Encrypt bytecode with per-instruction XOR keying
function encryptBytecode(bc, key) {
    return bc.map((instr, i) => {
        const kb = key[i % key.length];
        return {
            op: (instr.op ^ kb) & 0xFF,
            a: instr.a.map((arg, j) => (arg ^ key[(i+j+1) % key.length]) & 0xFFFF)
        };
    });
}

// ─── JUNK & OPAQUE ────────────────────────────────────────────────────────────

function junkCode() {
    const n = randName();
    const templates = [
        `local ${n}=${rand(1,999)}`,
        `local ${n}=type(nil)`,
        `local ${n}={}`,
        `local ${n}=(${rand(1,50)}+${rand(1,50)})`,
        `local ${n}='${randName(rand(3,8))}'`,
        `local ${n}=math.abs(${rand(1,100)})`,
    ];
    return templates[rand(0, templates.length-1)];
}

function opaqueTrue() {
    const opts = [
        '(1==1)','(not false)','(type("")=="string")','(0==0)','(#""==0)',
        '(math.pi>3)','(true)','((2+2)==4)','(not nil)',
    ];
    return opts[rand(0, opts.length-1)];
}

function opaqueFalse() {
    const opts = [
        '(1==0)','(false)','(type("")=="number")','(1>2)','(nil==1)',
        '(math.pi<3)','(not true)','((2+2)==5)',
    ];
    return opts[rand(0, opts.length-1)];
}

function deadBranch() {
    const v=randName();
    return `if ${opaqueFalse()} then local ${v}=${rand(1,9999)} end\n`;
}

// ─── SHUFFLE OPCODE MAP ───────────────────────────────────────────────────────

function shuffleOpcodes() {
    const fwd = {}; const rev = {};
    const pool = Array.from({length:50},(_,i)=>i+1);
    for (let i=pool.length-1;i>0;i--) { const j=rand(0,i); [pool[i],pool[j]]=[pool[j],pool[i]]; }
    for (let orig=1;orig<=50;orig++) { fwd[orig]=pool[orig-1]; rev[pool[orig-1]]=orig; }
    return {fwd, rev};
}

// ─── VM GENERATOR ─────────────────────────────────────────────────────────────

function generateVM(bc, consts, key, bcKey, opcodeMap) {
    const V = Array.from({length:40}, () => randName());
    const ps = randName(2); // push
    const pp = randName(2); // pop
    const cs = randName(2); // consts ref
    const vs = randName(2); // vars ref
    const sp = randName(3); // stack pointer
    const sd = randName(3); // stack data
    const iv = randName(3); // instruction pointer var

    const keyS = keyStr(key);
    const bcKeyS = keyStr(bcKey);

    // Build consts table
    const constParts = consts.map(c => {
        if (c.t === 'n') return `{t='n',v=${c.v}}`;
        if (c.t === 's') return `{t='s',v=${escStr(c.enc)},e=1}`;
        return `{t='s',v="",e=0}`;
    });
    const constStr = '{' + constParts.join(',') + '}';

    // Build bytecode table
    const fop = randName(2); // field op
    const fa = randName(2);  // field args
    const bcParts = bc.map(instr => `{${fop}=${instr.op},${fa}={${instr.a.join(',')}}}`);
    const bcStr = '{' + bcParts.join(',') + '}';

    // Shuffled handler for each opcode (at shuffled position)
    const shuffled = opcodeMap.fwd;
    const retOp = shuffled[OP.RET];

    const lines = [];
    const L = (s) => lines.push(s);

    L(`local function ${V[0]}()`);
    L(`local ${V[1]}=${keyS}`);
    L(`local ${V[2]}=${constStr}`);
    L(`local ${V[3]}=${bcStr}`);
    L(`local ${V[4]}=${bcKeyS}`);

    // Derived key for layer 3
    L(`local ${V[5]}={}`);
    L(`local ${V[6]}=0xDEADBEEF`);
    L(`for i=1,#${V[1]} do ${V[6]}=(${V[6]}*1664525+1013904223)&0xFFFFFFFF;${V[5]}[i]=(${V[1]}[i]~(${V[6]}>>(( (i-1)%24)))&0xFF)&0xFF end`);

    // Decrypt constants function
    L(`local function ${V[7]}(s,k,dk)`);
    L(`local r={}`);
    // Layer 3 reverse: XOR with derived key
    L(`local t3={} for i=1,#s do t3[i]=string.char((s:byte(i)~dk[((i-1)%#dk)+1])&0xFF)end s=table.concat(t3)`);
    // Layer 2 reverse: rotate -137
    L(`local t2={} for i=1,#s do t2[i]=string.char((s:byte(i)-137)%256)end s=table.concat(t2)`);
    // Layer 1: XOR
    L(`for i=1,#s do r[i]=string.char((s:byte(i)~k[((i-1)%#k)+1])&0xFF)end return table.concat(r)`);
    L(`end`);

    // Decrypt all string constants
    L(`for _,c in ipairs(${V[2]})do if c.t=='s' and c.e==1 then c.v=${V[7]}(c.v,${V[1]},${V[5]})end end`);

    // Decrypt bytecode
    L(`local ${V[8]}={}`);
    L(`for i,ins in ipairs(${V[3]})do`);
    L(`local kb=${V[4]}[((i-1)%#${V[4]})+1]`);
    L(`local op=(ins.${fop}~kb)&0xFF`);
    L(`local aa={}`);
    L(`for j,a in ipairs(ins.${fa})do aa[j]=(a~${V[4]}[((i+j)%#${V[4]})+1])&0xFFFF end`);
    L(`${V[8]}[i]={${fop}=op,${fa}=aa}`);
    L(`end`);
    L(`${V[3]}=${V[8]}`);

    // Stack implementation
    L(`local ${sd}={}`);
    L(`local ${sp}=0`);
    L(`local function ${ps}(x) ${sp}=${sp}+1;${sd}[${sp}]=x end`);
    L(`local function ${pp}() if ${sp}<1 then return nil end;local v=${sd}[${sp}];${sd}[${sp}]=nil;${sp}=${sp}-1;return v end`);

    L(`local ${vs}={}`);
    L(`local ${cs}=${V[2]}`);

    // Handler table - handlers stored at shuffled opcode positions
    const ht = randName(4);
    L(`local ${ht}={}`);

    // Define all handlers at shuffled positions
    const handlers = {
        [OP.LCONST]: `function(a) ${ps}(${cs}[a[1]].v) end`,
        [OP.LVAR]:   `function(a) ${ps}(${vs}[${cs}[a[1]].v]) end`,
        [OP.SVAR]:   `function(a) ${vs}[${cs}[a[1]].v]=${pp}() end`,
        [OP.LGLOBAL]:`function(a) local n=${cs}[a[1]].v;local v=${vs}[n];if v==nil then v=_G[n]end;${ps}(v) end`,
        [OP.SGLOBAL]:`function(a) _G[${cs}[a[1]].v]=${pp}() end`,
        [OP.CALL]:   `function(a) local n=a[1];local args={};for i=n,1,-1 do args[i]=${pp}()end;local f=${pp}();local r={f(table.unpack(args))};for i=#r,1,-1 do ${ps}(r[i])end end`,
        [OP.RET]:    `function(a) local n=a[1] or 0;local r={};for i=1,n do r[i]=${pp}()end;return 'R',table.unpack(r) end`,
        [OP.ADD]:    `function() local b,a=${pp}(),${pp}();${ps}(a+b) end`,
        [OP.SUB]:    `function() local b,a=${pp}(),${pp}();${ps}(a-b) end`,
        [OP.MUL]:    `function() local b,a=${pp}(),${pp}();${ps}(a*b) end`,
        [OP.DIV]:    `function() local b,a=${pp}(),${pp}();${ps}(a/b) end`,
        [OP.MOD]:    `function() local b,a=${pp}(),${pp}();${ps}(a%b) end`,
        [OP.POW]:    `function() local b,a=${pp}(),${pp}();${ps}(a^b) end`,
        [OP.CAT]:    `function() local b,a=${pp}(),${pp}();${ps}(a..b) end`,
        [OP.EQ]:     `function() local b,a=${pp}(),${pp}();${ps}(a==b) end`,
        [OP.NE]:     `function() local b,a=${pp}(),${pp}();${ps}(a~=b) end`,
        [OP.LT]:     `function() local b,a=${pp}(),${pp}();${ps}(a<b) end`,
        [OP.LE]:     `function() local b,a=${pp}(),${pp}();${ps}(a<=b) end`,
        [OP.GT]:     `function() local b,a=${pp}(),${pp}();${ps}(a>b) end`,
        [OP.GE]:     `function() local b,a=${pp}(),${pp}();${ps}(a>=b) end`,
        [OP.AND]:    `function() local b,a=${pp}(),${pp}();${ps}(a and b) end`,
        [OP.OR]:     `function() local b,a=${pp}(),${pp}();${ps}(a or b) end`,
        [OP.NOT]:    `function() ${ps}(not ${pp}()) end`,
        [OP.NEG]:    `function() ${ps}(-${pp}()) end`,
        [OP.LEN]:    `function() ${ps}(#${pp}()) end`,
        [OP.JMP]:    `function(a) return 'J',a[1] end`,
        [OP.JIF]:    `function(a) if ${pp}() then return 'J',a[1] end end`,
        [OP.JIFN]:   `function(a) if not ${pp}() then return 'J',a[1] end end`,
        [OP.NTBL]:   `function() ${ps}({}) end`,
        [OP.GTBL]:   `function() local k,t=${pp}(),${pp}();${ps}(t[k]) end`,
        [OP.STBL]:   `function() local v,k,t=${pp}(),${pp}(),${pp}();t[k]=v;${ps}(t) end`,
        [OP.NIL]:    `function() ${ps}(nil) end`,
        [OP.TRUE]:   `function() ${ps}(true) end`,
        [OP.FALSE]:  `function() ${ps}(false) end`,
        [OP.POP]:    `function() ${pp}() end`,
        [OP.DUP]:    `function() local v=${pp}();${ps}(v);${ps}(v) end`,
        [OP.CLOSE]:  `function(a) ${ps}(${cs}[a[1]].v) end`,
        [OP.NOP]:    `function() end`,
    };

    for (const [origOp, body] of Object.entries(handlers)) {
        const sop = shuffled[parseInt(origOp)];
        if (sop !== undefined) L(`${ht}[${sop}]=${body}`);
    }

    // Main dispatch loop
    const dispFn = randName(5);
    L(`local ${dispFn}`);
    L(`${dispFn}=function(${iv})`);
    L(`if ${iv}>#${V[3]} then return end`);
    L(`local ins=${V[3]}[${iv}]`);
    L(`local op=ins.${fop}`);
    L(`local fn=${ht}[op]`);
    L(`if not fn then return ${dispFn}(${iv}+1) end`);
    L(`local r1,r2,r3,r4,r5=fn(ins.${fa})`);
    L(`if r1=='J' then return ${dispFn}(r2) end`);
    L(`if op==${retOp} then return r2,r3,r4,r5 end`);
    L(`return ${dispFn}(${iv}+1)`);
    L(`end`);

    L(`return ${dispFn}(1)`);
    L(`end`);
    L(`return ${V[0]}()`);

    return lines.join(';');
}

// ─── ANTI TAMPER / ENV / LOGGER ───────────────────────────────────────────────

function antiProtect() {
    const v = Array.from({length:8}, () => randName(rand(4,7)));
    return [
        `if debug and debug.sethook then debug.sethook(function()end,"",0)end`,
        `if debug and debug.getinfo then debug.getinfo=function()return{what="C",source="[C]",short_src="[C]",currentline=-1}end end`,
        `local ${v[0]}=os and os.getenv;if ${v[0]} and ${v[0]}"LUA_DEBUG" then while true do end end`,
        `local ${v[1]}=newcclosure or function(f)return f end`,
        `print=${v[1]}(function()end);warn=${v[1]}(function()end)`,
        `local ${v[2]}=type(_G);if ${v[2]}~="table" then while true do end end`,
        `local ${v[3]}=os and os.clock;if ${v[3]} then local ${v[4]}=${v[3]}();local ${v[5]}=0;for ${v[6]}=1,2000 do ${v[5]}=${v[5]}+${v[6]} end;if ${v[3]}()-${v[4]}>0.5 then while true do end end end`,
        `local ${v[7]}=tostring(tostring);pcall(function()tostring=tostring end);if tostring(tostring)~=${v[7]} then while true do end end`,
    ].join(';');
}

// ─── OUTER WRAP (single line) ─────────────────────────────────────────────────

function outerWrap(innerCode) {
    const k = genKey(32);
    const bytes = xorBuf(innerCode, k);
    const [v1, v2, v3, v4] = Array.from({length:4}, () => randName());
    return `return(function()local ${v1}=${escStr(bytes)};local ${v2}=${keyStr(k)};local ${v3}={};for i=1,#${v1} do ${v3}[i]=string.char((${v1}:byte(i)~${v2}[((i-1)%#${v2})+1])&0xFF)end;local ${v4}=load(table.concat(${v3}));if ${v4} then return ${v4}()end end)()`;
}

// ─── MAIN OBFUSCATE ───────────────────────────────────────────────────────────

function obfuscate(source) {
    const tokens = tokenize(source);
    const { bc, consts } = compile(tokens);

    const key = genKey(32);
    encryptConsts(consts, key);

    const junkBc = [];
    for (const instr of bc) {
        junkBc.push(instr);
        if (Math.random() < 0.2) junkBc.push({ op: OP.NOP, a: [] });
    }

    const opcodeMap = shuffleOpcodes();
    const mutated = junkBc.map(instr => ({
        op: opcodeMap.fwd[instr.op] ?? instr.op,
        a: [...instr.a]
    }));

    const bcKey = genKey(32);
    const encBc = encryptBytecode(mutated, bcKey);
    const vmCode = generateVM(encBc, consts, key, bcKey, opcodeMap);

    const junk = Array.from({length: rand(3,6)}, () => junkCode()).join(';');
    const dead = Array.from({length: rand(2,4)}, () => {
        const v = randName();
        return `if ${opaqueFalse()} then local ${v}=${rand(1,9999)} end`;
    }).join(';');

    const protect = antiProtect();
    const uid = randName(16);
    const inner = `--[[ICE:${uid}]] return(function()${protect};${junk};${dead};${vmCode}end)()`;

    return outerWrap(inner);
}

// ─── CLI ENTRY ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
if (args.length === 2) {
    const src = fs.readFileSync(args[0], 'utf8');
    const out = obfuscate(src);
    fs.writeFileSync(args[1], out, 'utf8');
    console.log(`done: ${src.length}b → ${out.length}b`);
} else if (args.length === 1) {
    const src = fs.readFileSync(args[0], 'utf8');
    process.stdout.write(obfuscate(src));
} else {
    let src = '';
    process.stdin.on('data', d => src += d);
    process.stdin.on('end', () => process.stdout.write(obfuscate(src)));
}

module.exports = { obfuscate };

