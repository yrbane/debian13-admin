<?php
/**
 * Error page with WebGL 3D animation (Three.js)
 * Deployed by debian13-server.sh — Do not edit manually
 *
 * - Error code in 3D with neon effect
 * - 4xx: amber/orange, 5xx: red
 * - Debug info for trusted IPs
 * - JSON API response if Accept: application/json
 * - 5xx notification via error-notify.php
 */

require_once __DIR__ . '/trusted-ips.php';
require_once __DIR__ . '/error-notify.php';

// Get error code — REDIRECT_STATUS is most reliable with Apache ErrorDocument
$error_code = (int) ($_SERVER['REDIRECT_STATUS'] ?? $_GET['code'] ?? 500);

// Comprehensive error messages (400-599)
$errors = [
    // 4xx Client errors
    400 => ['title' => 'Requete invalide',           'message' => 'Le serveur n\'a pas pu comprendre votre requete.'],
    401 => ['title' => 'Authentification requise',    'message' => 'Vous devez vous identifier pour acceder a cette ressource.'],
    402 => ['title' => 'Paiement requis',             'message' => 'Un paiement est necessaire pour acceder a cette ressource.'],
    403 => ['title' => 'Acces interdit',              'message' => 'Vous n\'avez pas les permissions pour acceder a cette ressource.'],
    404 => ['title' => 'Page introuvable',            'message' => 'La page que vous recherchez n\'existe pas ou a ete deplacee.'],
    405 => ['title' => 'Methode non autorisee',       'message' => 'La methode HTTP utilisee n\'est pas autorisee pour cette ressource.'],
    406 => ['title' => 'Non acceptable',              'message' => 'Le serveur ne peut pas produire une reponse acceptable.'],
    407 => ['title' => 'Authentification proxy requise', 'message' => 'Vous devez vous authentifier aupres du proxy.'],
    408 => ['title' => 'Delai d\'attente depasse',    'message' => 'Le serveur a mis trop de temps a recevoir la requete.'],
    409 => ['title' => 'Conflit',                     'message' => 'La requete est en conflit avec l\'etat actuel de la ressource.'],
    410 => ['title' => 'Ressource supprimee',         'message' => 'Cette ressource a ete definitivement supprimee.'],
    411 => ['title' => 'Longueur requise',            'message' => 'Le header Content-Length est requis.'],
    412 => ['title' => 'Precondition echouee',        'message' => 'Une precondition de la requete n\'est pas satisfaite.'],
    413 => ['title' => 'Requete trop volumineuse',    'message' => 'Les donnees envoyees depassent la limite autorisee.'],
    414 => ['title' => 'URI trop longue',             'message' => 'L\'adresse demandee est trop longue.'],
    415 => ['title' => 'Type non supporte',           'message' => 'Le format des donnees envoyees n\'est pas supporte.'],
    416 => ['title' => 'Plage non satisfaisable',     'message' => 'La plage demandee n\'est pas disponible.'],
    417 => ['title' => 'Attente echouee',             'message' => 'Le serveur ne peut pas satisfaire les attentes de la requete.'],
    418 => ['title' => 'Je suis une theiere',         'message' => 'Le serveur refuse de preparer du cafe car c\'est une theiere.'],
    421 => ['title' => 'Requete mal dirigee',         'message' => 'La requete a ete dirigee vers un serveur inadapte.'],
    422 => ['title' => 'Entite non traitable',        'message' => 'La syntaxe est correcte mais les donnees sont non traitables.'],
    423 => ['title' => 'Ressource verrouillee',       'message' => 'La ressource est actuellement verrouillee.'],
    424 => ['title' => 'Dependance echouee',          'message' => 'La requete a echoue a cause d\'une dependance.'],
    425 => ['title' => 'Trop tot',                    'message' => 'Le serveur refuse de traiter une requete potentiellement rejouee.'],
    426 => ['title' => 'Mise a jour requise',         'message' => 'Le client doit passer a un protocole superieur.'],
    428 => ['title' => 'Precondition requise',        'message' => 'Le serveur exige une requete conditionnelle.'],
    429 => ['title' => 'Trop de requetes',            'message' => 'Vous avez envoye trop de requetes. Reessayez plus tard.'],
    431 => ['title' => 'En-tetes trop volumineux',    'message' => 'Les en-tetes de la requete sont trop volumineux.'],
    451 => ['title' => 'Indisponible pour raisons legales', 'message' => 'L\'acces a cette ressource est restreint pour des raisons legales.'],

    // 5xx Server errors
    500 => ['title' => 'Erreur interne',              'message' => 'Une erreur interne s\'est produite. Nos equipes sont informees.'],
    501 => ['title' => 'Non implemente',              'message' => 'Le serveur ne supporte pas la fonctionnalite requise.'],
    502 => ['title' => 'Passerelle incorrecte',       'message' => 'Le serveur a recu une reponse invalide d\'un serveur en amont.'],
    503 => ['title' => 'Service indisponible',        'message' => 'Le serveur est temporairement indisponible. Reessayez dans quelques instants.'],
    504 => ['title' => 'Delai passerelle depasse',    'message' => 'Le serveur en amont n\'a pas repondu dans les delais.'],
    505 => ['title' => 'Version HTTP non supportee',  'message' => 'Le serveur ne supporte pas la version HTTP utilisee.'],
    506 => ['title' => 'Negociation circulaire',      'message' => 'Erreur de configuration de negociation de contenu.'],
    507 => ['title' => 'Stockage insuffisant',        'message' => 'Le serveur ne dispose pas d\'assez d\'espace pour traiter la requete.'],
    508 => ['title' => 'Boucle detectee',             'message' => 'Le serveur a detecte une boucle infinie.'],
    510 => ['title' => 'Extensions manquantes',       'message' => 'Des extensions supplementaires sont requises.'],
    511 => ['title' => 'Authentification reseau requise', 'message' => 'Vous devez vous authentifier aupres du reseau.'],
];

$error = $errors[$error_code] ?? ['title' => 'Erreur', 'message' => 'Une erreur inattendue s\'est produite.'];
$is_trusted = is_trusted_ip();
$is_5xx = ($error_code >= 500);
$color_class = $is_5xx ? 'is-5xx' : 'is-4xx';

// Set proper HTTP response code
http_response_code($error_code);

// Send notification for 5xx errors
if ($is_5xx) {
    send_error_notification($error_code);
}

// JSON API: if Accept header requests JSON
$accept = $_SERVER['HTTP_ACCEPT'] ?? '';
if (stripos($accept, 'application/json') !== false) {
    header('Content-Type: application/json; charset=UTF-8');
    $response = [
        'error' => true,
        'code'  => $error_code,
        'title' => $error['title'],
        'message' => $error['message'],
        'timestamp' => date('c'),
    ];
    if ($is_trusted) {
        $response['debug'] = [
            'ip'         => $_SERVER['REMOTE_ADDR'] ?? null,
            'uri'        => $_SERVER['REQUEST_URI'] ?? null,
            'method'     => $_SERVER['REQUEST_METHOD'] ?? null,
            'referer'    => $_SERVER['HTTP_REFERER'] ?? null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'server'     => $_SERVER['SERVER_NAME'] ?? null,
        ];
    }
    echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// Collect headers for debug
$request_headers = [];
if ($is_trusted) {
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $header_name = str_replace('_', '-', substr($key, 5));
            $request_headers[$header_name] = $value;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Erreur <?= $error_code ?> — <?= htmlspecialchars($error['title']) ?></title>
    <link rel="stylesheet" href="/errorpages/css/error.css">
</head>
<body>
    <canvas id="error-canvas"></canvas>

    <div class="overlay">
        <div class="error-card">
            <div class="error-code <?= $color_class ?>"><?= $error_code ?></div>
            <h1 class="error-title"><?= htmlspecialchars($error['title']) ?></h1>
            <p class="error-message"><?= htmlspecialchars($error['message']) ?></p>

            <a href="/" class="btn-back">&#8592; Retour</a>

            <?php if ($is_trusted): ?>
            <div class="debug">
                <div class="debug-title">Informations de debug (IP de confiance)</div>
                <div class="debug-grid">
                    <div class="debug-item">
                        <span class="debug-key">IP</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'N/A') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">URI</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['REQUEST_URI'] ?? 'N/A') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">Methode</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? 'N/A') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">Referer</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['HTTP_REFERER'] ?? 'Direct') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">User-Agent</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'N/A') ?></span>
                    </div>
                    <?php if (!empty($request_headers)): ?>
                    <div class="debug-item">
                        <span class="debug-key">Headers</span>
                        <span class="debug-value"><?= htmlspecialchars(implode(', ', array_keys($request_headers))) ?></span>
                    </div>
                    <?php endif; ?>
                    <div class="debug-item">
                        <span class="debug-key">Server</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_NAME'] ?? 'N/A') ?>:<?= htmlspecialchars($_SERVER['SERVER_PORT'] ?? 'N/A') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">Protocole</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_PROTOCOL'] ?? 'N/A') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">Document Root</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? 'N/A') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">Script</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['SCRIPT_FILENAME'] ?? 'N/A') ?></span>
                    </div>
                    <?php if (!empty($_SERVER['REDIRECT_URL'])): ?>
                    <div class="debug-item">
                        <span class="debug-key">Redirect URL</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['REDIRECT_URL']) ?></span>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($_SERVER['REDIRECT_STATUS'])): ?>
                    <div class="debug-item">
                        <span class="debug-key">Redirect Status</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['REDIRECT_STATUS']) ?></span>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($_SERVER['QUERY_STRING'])): ?>
                    <div class="debug-item">
                        <span class="debug-key">Query String</span>
                        <span class="debug-value"><?= htmlspecialchars($_SERVER['QUERY_STRING']) ?></span>
                    </div>
                    <?php endif; ?>
                    <div class="debug-item">
                        <span class="debug-key">Timestamp</span>
                        <span class="debug-value"><?= date('Y-m-d H:i:s T') ?></span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">PHP</span>
                        <span class="debug-value"><?= PHP_VERSION ?> | Mem: <?= round(memory_get_usage(true) / 1048576, 1) ?>MB</span>
                    </div>
                    <div class="debug-item">
                        <span class="debug-key">Load</span>
                        <span class="debug-value"><?= implode(' ', sys_getloadavg()) ?></span>
                    </div>
                </div>

                <details>
                    <summary>$_SERVER complet</summary>
                    <pre><?= htmlspecialchars(print_r($_SERVER, true)) ?></pre>
                </details>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <script type="importmap">
    {
        "imports": {
            "three": "https://cdn.jsdelivr.net/npm/three@0.175.0/build/three.module.js",
            "three/addons/": "https://cdn.jsdelivr.net/npm/three@0.175.0/examples/jsm/"
        }
    }
    </script>
    <script type="module">
    import * as THREE from 'three';
    import { FontLoader } from 'three/addons/loaders/FontLoader.js';
    import { TextGeometry } from 'three/addons/geometries/TextGeometry.js';

    const canvas = document.getElementById('error-canvas');
    const errorCode = '<?= $error_code ?>';
    const is5xx = <?= $is_5xx ? 'true' : 'false' ?>;
    const mainColor = is5xx ? 0xdc2626 : 0xf59e0b;

    // Detect WebGL support
    let renderer;
    try {
        renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    } catch (e) {
        document.body.classList.add('no-webgl');
        throw e;
    }

    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x0a0a1a, 1);

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x0a0a1a, 0.015);

    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 0, 8);

    // Ambient light
    scene.add(new THREE.AmbientLight(0x111122, 0.5));

    // Two orbiting point lights
    const light1 = new THREE.PointLight(mainColor, 2, 30);
    const light2 = new THREE.PointLight(0xdc5c3b, 1.5, 30);
    scene.add(light1, light2);

    // Particles — radial explosion effect
    const particleCount = 300;
    const pGeometry = new THREE.BufferGeometry();
    const pPositions = new Float32Array(particleCount * 3);
    const pVelocities = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
        const r = 3 + Math.random() * 12;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        pPositions[i * 3]     = r * Math.sin(phi) * Math.cos(theta);
        pPositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
        pPositions[i * 3 + 2] = r * Math.cos(phi);
        pVelocities[i * 3]     = (Math.random() - 0.5) * 0.005;
        pVelocities[i * 3 + 1] = (Math.random() - 0.5) * 0.005;
        pVelocities[i * 3 + 2] = (Math.random() - 0.5) * 0.005;
    }
    pGeometry.setAttribute('position', new THREE.BufferAttribute(pPositions, 3));

    const pMaterial = new THREE.PointsMaterial({
        color: mainColor,
        size: 0.04,
        transparent: true,
        opacity: 0.6,
        sizeAttenuation: true,
    });
    const particles = new THREE.Points(pGeometry, pMaterial);
    scene.add(particles);

    // Load font and create 3D text
    const loader = new FontLoader();
    let textMesh, wireframeMesh;

    loader.load('https://cdn.jsdelivr.net/npm/three@0.175.0/examples/fonts/helvetiker_bold.typeface.json', (font) => {
        const textGeo = new TextGeometry(errorCode, {
            font: font,
            size: 2.5,
            depth: 0.6,
            curveSegments: 8,
            bevelEnabled: true,
            bevelThickness: 0.05,
            bevelSize: 0.04,
            bevelSegments: 4,
        });
        textGeo.computeBoundingBox();
        const center = new THREE.Vector3();
        textGeo.boundingBox.getCenter(center);
        textGeo.translate(-center.x, -center.y, -center.z);

        // Solid mesh
        const material = new THREE.MeshStandardMaterial({
            color: mainColor,
            metalness: 0.7,
            roughness: 0.2,
            emissive: mainColor,
            emissiveIntensity: 0.3,
        });
        textMesh = new THREE.Mesh(textGeo, material);
        scene.add(textMesh);

        // Wireframe overlay (neon pulse)
        const wireMat = new THREE.MeshBasicMaterial({
            color: mainColor,
            wireframe: true,
            transparent: true,
            opacity: 0.15,
        });
        wireframeMesh = new THREE.Mesh(textGeo, wireMat);
        scene.add(wireframeMesh);
    });

    // Animation loop
    const clock = new THREE.Clock();

    function animate() {
        requestAnimationFrame(animate);
        const t = clock.getElapsedTime();

        // Orbit lights
        light1.position.set(Math.sin(t * 0.7) * 6, Math.cos(t * 0.5) * 3, Math.sin(t * 0.3) * 4);
        light2.position.set(Math.cos(t * 0.4) * 5, Math.sin(t * 0.6) * 4, Math.cos(t * 0.8) * 3);

        // Rotate text
        if (textMesh) {
            textMesh.rotation.y = Math.sin(t * 0.3) * 0.15;
            textMesh.position.y = Math.sin(t * 0.5) * 0.15;
        }
        if (wireframeMesh) {
            wireframeMesh.rotation.y = Math.sin(t * 0.3) * 0.15;
            wireframeMesh.position.y = Math.sin(t * 0.5) * 0.15;
            wireframeMesh.material.opacity = 0.1 + Math.sin(t * 2) * 0.08;
        }

        // Animate particles
        const pos = pGeometry.attributes.position.array;
        for (let i = 0; i < particleCount; i++) {
            pos[i * 3]     += pVelocities[i * 3];
            pos[i * 3 + 1] += pVelocities[i * 3 + 1];
            pos[i * 3 + 2] += pVelocities[i * 3 + 2];
        }
        pGeometry.attributes.position.needsUpdate = true;
        particles.rotation.y = t * 0.02;

        renderer.render(scene, camera);
    }
    animate();

    // Resize handler
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
    </script>
</body>
</html>
