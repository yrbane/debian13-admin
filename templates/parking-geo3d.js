/* geo3d — signature géométrique 3D de yrbane, variante « parking ».
 * Rendu canvas 2D pur (aucune dépendance externe → compatible CSP 'self').
 * Polyèdres wireframe imbriqués (sphère géodésique + solides de Platon),
 * glow des sommets, parallaxe souris. Chaque chargement varie ALÉATOIREMENT :
 * palette, solides, sens/vitesses de rotation, niveau de subdivision, échelles.
 * Déployé par debian13-server.sh — ne pas éditer à la main. */
(function () {
    var c = document.getElementById('geo-canvas');
    if (!c) return;
    var ctx = c.getContext('2d');
    if (!ctx) return;

    var DPR = Math.min(window.devicePixelRatio || 1, 2);
    var needResize = false;

    function canvasResize() {
        var nw = Math.round(c.clientWidth * DPR), nh = Math.round(c.clientHeight * DPR);
        if (c.width !== nw || c.height !== nh) { c.width = nw; c.height = nh; }
    }
    canvasResize();
    window.addEventListener('resize', function () { needResize = true; });

    var mx = 0, my = 0;
    document.addEventListener('mousemove', function (e) {
        mx = (e.clientX / window.innerWidth - 0.5) * 2;
        my = (e.clientY / window.innerHeight - 0.5) * 2;
    });

    // ---- Aléatoire ----
    function rand(a, b) { return a + Math.random() * (b - a); }
    function pick(a) { return a[(Math.random() * a.length) | 0]; }
    function sign() { return Math.random() < 0.5 ? -1 : 1; }

    // ---- Solides de base (sommets normalisés sur la sphère unité + faces) ----
    var PHI = (1 + Math.sqrt(5)) / 2;
    function norm(V) {
        V.forEach(function (v) {
            var l = Math.hypot(v[0], v[1], v[2]) || 1;
            v[0] /= l; v[1] /= l; v[2] /= l;
        });
        return V;
    }
    var SOLIDS = {
        ico: {
            v: norm([[-1, PHI, 0], [1, PHI, 0], [-1, -PHI, 0], [1, -PHI, 0],
                     [0, -1, PHI], [0, 1, PHI], [0, -1, -PHI], [0, 1, -PHI],
                     [PHI, 0, -1], [PHI, 0, 1], [-PHI, 0, -1], [-PHI, 0, 1]]),
            f: [[0, 11, 5], [0, 5, 1], [0, 1, 7], [0, 7, 10], [0, 10, 11], [1, 5, 9],
                [5, 11, 4], [11, 10, 2], [10, 7, 6], [7, 1, 8], [3, 9, 4], [3, 4, 2],
                [3, 2, 6], [3, 6, 8], [3, 8, 9], [4, 9, 5], [2, 4, 11], [6, 2, 10],
                [8, 6, 7], [9, 8, 1]]
        },
        oct: {
            v: norm([[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]]),
            f: [[0, 2, 4], [0, 4, 3], [0, 3, 5], [0, 5, 2], [1, 2, 5], [1, 5, 3], [1, 3, 4], [1, 4, 2]]
        },
        tetra: {
            v: norm([[1, 1, 1], [1, -1, -1], [-1, 1, -1], [-1, -1, 1]]),
            f: [[0, 1, 2], [0, 3, 1], [0, 2, 3], [1, 3, 2]]
        },
        cube: {
            v: norm([[-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1],
                     [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]]),
            f: [[0, 1, 2], [0, 2, 3], [4, 5, 6], [4, 6, 7], [0, 1, 5], [0, 5, 4],
                [2, 3, 7], [2, 7, 6], [1, 2, 6], [1, 6, 5], [0, 3, 7], [0, 7, 4]]
        }
    };

    function subdiv(V, F, iter) {
        for (var it = 0; it < iter; it++) {
            var mc = {}, nV = V.map(function (v) { return v.slice(); }), nF = [];
            function mid(i, j) {
                var k = Math.min(i, j) + '_' + Math.max(i, j);
                if (mc[k] !== undefined) return mc[k];
                var a = nV[i], b = nV[j], m = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2];
                var l = Math.hypot(m[0], m[1], m[2]) || 1;
                m[0] /= l; m[1] /= l; m[2] /= l;
                mc[k] = nV.length; nV.push(m);
                return mc[k];
            }
            F.forEach(function (f) {
                var a = mid(f[0], f[1]), b = mid(f[1], f[2]), d = mid(f[2], f[0]);
                nF.push([f[0], a, d], [f[1], b, a], [f[2], d, b], [a, b, d]);
            });
            V = nV; F = nF;
        }
        return { v: V, f: F };
    }

    function edges(F) {
        var s = {}, e = [];
        F.forEach(function (f) {
            for (var i = 0; i < 3; i++) {
                var a = f[i], b = f[(i + 1) % 3], k = Math.min(a, b) + '_' + Math.max(a, b);
                if (!s[k]) { s[k] = 1; e.push([a, b]); }
            }
        });
        return e;
    }

    // ---- Palettes (RGB « r,g,b ») — vives sur fond sombre, dans l'esprit yrbane ----
    var PALETTES = [
        ['108,99,255', '0,212,170', '255,107,107'],   // signature yrbane (violet/teal/rouge)
        ['107,219,219', '220,92,59', '148,163,184'],   // parking (cyan/orange/ardoise)
        ['99,102,241', '34,211,238', '244,114,182'],   // indigo/cyan/rose
        ['16,185,129', '59,130,246', '234,179,8'],      // émeraude/bleu/ambre
        ['139,92,246', '45,212,191', '236,72,153']      // violet/turquoise/magenta
    ];
    var palette = pick(PALETTES);

    // ---- Construction aléatoire des 3 couches imbriquées ----
    var solidKeys = ['ico', 'oct', 'tetra', 'cube'];
    var geoBase = pick(['ico', 'oct']);          // base de la sphère géodésique
    var subLvl = 1 + ((Math.random() < 0.5) ? 1 : 0); // 1 ou 2 subdivisions
    var geo = subdiv(SOLIDS[geoBase].v, SOLIDS[geoBase].f, subLvl);

    // Couche 0 = sphère géodésique ; couches 1 et 2 = solides tirés au hasard
    // (chaque couche garde v ET f du MÊME solide, sinon les arêtes sont fausses).
    var s1 = SOLIDS[pick(solidKeys)], s2 = SOLIDS[pick(solidKeys)];
    var geoSets = [
        { v: geo.v, f: geo.f },
        { v: s1.v, f: s1.f },
        { v: s2.v, f: s2.f }
    ];

    var baseSpd = [rand(0.35, 0.6), rand(0.6, 0.95), rand(1.0, 1.5)];
    var gLayers = [];
    for (var li = 0; li < 3; li++) {
        var col = palette[li];
        gLayers.push({
            sc: [1.5, 0.85, 0.4][li] * rand(0.9, 1.15),
            spd: [sign() * baseSpd[li] * rand(0.7, 1.3),
                  sign() * baseSpd[li] * rand(0.5, 1.0),
                  sign() * baseSpd[li] * rand(0.3, 0.8)],
            mInf: [0.6, 0.7, 0.9][li],
            lw: [0.6, 1.2, 1.8][li],
            stroke: 'rgba(' + col + ',' + [0.30, 0.25, 0.42][li] + ')',
            pa: [0.25, 0.5, 0.7][li],
            pr: [1.5, 2.5, 4][li],
            col: col
        });
    }

    for (var li = 0; li < 3; li++) {
        var g = geoSets[li], E = edges(g.f), nv = g.v.length, ne = E.length;
        var fv = new Float64Array(nv * 3);
        for (var i = 0; i < nv; i++) { fv[i * 3] = g.v[i][0]; fv[i * 3 + 1] = g.v[i][1]; fv[i * 3 + 2] = g.v[i][2]; }
        var fe = new Uint16Array(ne * 2);
        for (var i = 0; i < ne; i++) { fe[i * 2] = E[i][0]; fe[i * 2 + 1] = E[i][1]; }
        gLayers[li].fv = fv; gLayers[li].fe = fe; gLayers[li].nv = nv; gLayers[li].ne = ne;
        gLayers[li].proj = new Float64Array(nv * 2);
    }

    function makeGlow(col, alpha, radius) {
        var sz = Math.max(2, Math.ceil(radius * 2) | 0);
        var oc = document.createElement('canvas'); oc.width = sz; oc.height = sz;
        var ox = oc.getContext('2d');
        var gr = ox.createRadialGradient(sz / 2, sz / 2, 0, sz / 2, sz / 2, sz / 2);
        gr.addColorStop(0, 'rgba(' + col + ',' + alpha + ')');
        gr.addColorStop(1, 'rgba(' + col + ',0)');
        ox.fillStyle = gr; ox.fillRect(0, 0, sz, sz);
        return oc;
    }
    var sprites = [];
    function rebuildSprites() {
        sprites = [];
        for (var i = 0; i < 3; i++) sprites[i] = makeGlow(gLayers[i].col, gLayers[i].pa, gLayers[i].pr * DPR * 2.5);
    }
    rebuildSprites();

    var R = new Float64Array(9);
    function buildRot(ay, ax, az) {
        var cy = Math.cos(ay), sy = Math.sin(ay), cx = Math.cos(ax), sx = Math.sin(ax), cz = Math.cos(az), sz = Math.sin(az);
        R[0] = cz * cy + sz * sx * sy; R[1] = sz * cx; R[2] = -cz * sy + sz * sx * cy;
        R[3] = -sz * cy + cz * sx * sy; R[4] = cz * cx; R[5] = sz * sy + cz * sx * cy;
        R[6] = cx * sy; R[7] = -sx; R[8] = cx * cy;
    }

    var smx = 0, smy = 0, t = rand(0, 120), lastT = 0;
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function draw(now) {
        requestAnimationFrame(draw);
        if (!lastT) lastT = now;
        t += (now - lastT) * (reduce ? 0.0000012 : 0.000004);
        lastT = now;
        if (needResize) { canvasResize(); rebuildSprites(); needResize = false; }

        smx += (mx - smx) * 0.035; smy += (my - smy) * 0.035;
        var W = c.width, H = c.height, hw = W * 0.5, hh = H * 0.5, fov = Math.min(W, H) * 0.9;
        ctx.clearRect(0, 0, W, H);
        var pulse = 1 + Math.sin(t * 1.5) * 0.04;

        for (var li = 0; li < 3; li++) {
            var L = gLayers[li], fv = L.fv, fe = L.fe, nv = L.nv, ne = L.ne, pr = L.proj;
            var sc_ = L.sc * (li === 0 ? pulse : 1);
            buildRot(t * L.spd[0] + smx * L.mInf, t * L.spd[1] + smy * L.mInf, t * L.spd[2]);
            for (var i = 0, i3 = 0, i2 = 0; i < nv; i++, i3 += 3, i2 += 2) {
                var vx = fv[i3], vy = fv[i3 + 1], vz = fv[i3 + 2];
                var tz = (R[6] * vx + R[7] * vy + R[8] * vz) * sc_ - 3.5;
                var f = fov / (-tz);
                pr[i2] = hw + (R[0] * vx + R[1] * vy + R[2] * vz) * sc_ * f;
                pr[i2 + 1] = hh - (R[3] * vx + R[4] * vy + R[5] * vz) * sc_ * f;
            }
            ctx.lineWidth = L.lw * DPR; ctx.strokeStyle = L.stroke; ctx.beginPath();
            for (var i = 0, i2 = 0; i < ne; i++, i2 += 2) {
                var ai = fe[i2] << 1, bi = fe[i2 + 1] << 1;
                ctx.moveTo(pr[ai], pr[ai + 1]); ctx.lineTo(pr[bi], pr[bi + 1]);
            }
            ctx.stroke();
            if (li > 0) {
                var spr = sprites[li], sh = spr.width * 0.5;
                for (var i = 0, i2 = 0; i < nv; i++, i2 += 2) ctx.drawImage(spr, pr[i2] - sh, pr[i2 + 1] - sh);
            }
        }
    }
    requestAnimationFrame(draw);
})();
