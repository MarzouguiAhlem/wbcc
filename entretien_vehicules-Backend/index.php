<?php
header('Content-Type: application/json');
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once 'db.php'; // Fichier de connexion à la base de données

// Clé secrète pour JWT
define('JWT_SECRET', 'votre_clé_secrète');

// Fonction pour générer un token JWT
function generateJWT($userId) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload = json_encode(['id' => $userId, 'exp' => time() + 3600]); // 1 heure d'expiration
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

// Fonction pour vérifier le token JWT
function validateJWT($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    list($header, $payload, $signature) = $parts;

    // Vérification de la signature
    $expectedSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(hash_hmac('sha256', $header . '.' . $payload, JWT_SECRET, true)));
    
    if ($signature !== $expectedSignature) {
        return false;
    }

    // Vérification de l'expiration
    $payloadData = json_decode(base64_decode($payload), true);
    return $payloadData['exp'] > time();
}

// Fonction pour vérifier l'existence d'un chauffeur
function chauffeurExists($conn, $email) {
    $stmt = $conn->prepare("SELECT * FROM chauffeurs WHERE email = :email");
    $stmt->execute(['email' => $email]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Fonction pour vérifier l'existence d'un véhicule
function vehiculeExists($conn, $immatriculation) {
    $stmt = $conn->prepare("SELECT * FROM vehicules WHERE immatriculation = :immatriculation");
    $stmt->execute(['immatriculation' => $immatriculation]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Fonction pour obtenir tous les chauffeurs
function getChauffeurs($conn) {
    $stmt = $conn->prepare("SELECT * FROM chauffeurs");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Fonction pour ajouter un chauffeur
function addChauffeur($conn, $nom, $email, $mot_de_passe) {
    if (chauffeurExists($conn, $email)) {
        return ['message' => 'Chauffeur déjà existant', 'status' => false];
    }
    
    $stmt = $conn->prepare("INSERT INTO chauffeurs (nom, email, mot_de_passe) VALUES (:nom, :email, :mot_de_passe)");
    $stmt->execute(['nom' => $nom, 'email' => $email, 'mot_de_passe' => password_hash($mot_de_passe, PASSWORD_DEFAULT)]);
    return ['message' => 'Chauffeur ajouté', 'id' => $conn->lastInsertId(), 'status' => true];
}

// Fonction pour obtenir tous les véhicules
function getVehicules($conn) {
    $stmt = $conn->prepare("SELECT * FROM vehicules");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Fonction pour ajouter un véhicule
function addVehicule($conn, $marque, $modele, $immatriculation) {
    if (vehiculeExists($conn, $immatriculation)) {
        return ['message' => 'Véhicule déjà existant', 'status' => false];
    }

    $stmt = $conn->prepare("INSERT INTO vehicules (marque, modele, immatriculation) VALUES (:marque, :modele, :immatriculation)");
    $stmt->execute(['marque' => $marque, 'modele' => $modele, 'immatriculation' => $immatriculation]);
    return ['message' => 'Véhicule ajouté', 'id' => $conn->lastInsertId(), 'status' => true];
}

// Fonction pour ajouter un entretien
function addEntretien($conn, $type, $date, $vehicule_id, $chauffeur_id) {
    $stmt = $conn->prepare("INSERT INTO entretiens (type, date, vehicule_id, chauffeur_id) VALUES (:type, :date, :vehicule_id, :chauffeur_id)");
    $stmt->execute(['type' => $type, 'date' => $date, 'vehicule_id' => $vehicule_id, 'chauffeur_id' => $chauffeur_id]);
    return ['message' => 'Entretien ajouté', 'id' => $conn->lastInsertId()];
}

// Fonction pour ajouter un suivi
function addSuivi($conn, $entretien_id, $kilometrage, $carburant, $photo_carburant) {
    $stmt = $conn->prepare("INSERT INTO suivi (entretien_id, kilometrage, carburant, photo_carburant) VALUES (:entretien_id, :kilometrage, :carburant, :photo_carburant)");
    $stmt->execute(['entretien_id' => $entretien_id, 'kilometrage' => $kilometrage, 'carburant' => $carburant, 'photo_carburant' => $photo_carburant]);
    return ['message' => 'Suivi ajouté', 'id' => $conn->lastInsertId()];
}

// Fonction pour ajouter un nettoyage
function addNettoyage($conn, $entretien_id, $photo_avant, $photo_apres) {
    $stmt = $conn->prepare("INSERT INTO nettoyage (entretien_id, photo_avant, photo_apres) VALUES (:entretien_id, :photo_avant, :photo_apres)");
    $stmt->execute(['entretien_id' => $entretien_id, 'photo_avant' => $photo_avant, 'photo_apres' => $photo_apres]);
    return ['message' => 'Nettoyage ajouté', 'id' => $conn->lastInsertId()];
}


// Fonction pour ajouter un carburant
function addCarburant($conn, $entretien_id, $montant, $litres, $facture) {
    $stmt = $conn->prepare("INSERT INTO carburant (entretien_id, montant, litres, facture) VALUES (:entretien_id, :montant, :litres, :facture)");
    $stmt->execute(['entretien_id' => $entretien_id, 'montant' => $montant, 'litres' => $litres, 'facture' => $facture]);
    return ['message' => 'Carburant ajouté', 'id' => $conn->lastInsertId()];
}

// Fonction de connexion
function login($conn, $email, $mot_de_passe) {
    $stmt = $conn->prepare("SELECT * FROM chauffeurs WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $chauffeur = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Débogage : afficher les informations de l'utilisateur récupéré
    if ($chauffeur) {
        error_log("Chauffeur trouvé : " . json_encode($chauffeur));
    } else {
        error_log("Aucun chauffeur trouvé avec l'email : $email");
    }

    if ($chauffeur && password_verify($mot_de_passe, $chauffeur['mot_de_passe'])) {
        $token = generateJWT($chauffeur['id']);
        return ['message' => 'Connexion réussie', 'token' => $token];
    }

    return ['message' => 'Identifiants invalides'];
}


function logout() {
    // En pratique, vous n'avez pas besoin de faire quoi que ce soit ici pour le JWT.
    // Juste une indication que la déconnexion a réussi.
    return ['message' => 'Déconnexion réussie'];
}






















//************************************ */ Route pour gérer les requêtes
$requestMethod = $_SERVER['REQUEST_METHOD'];

switch ($requestMethod) {
    case 'GET':
        if (isset($_GET['action'])) {
            switch ($_GET['action']) {
                case 'getChauffeurs':
                    echo json_encode(getChauffeurs($conn));
                    break;
                case 'getVehicules':
                    echo json_encode(getVehicules($conn));
                    break;
                case 'logout':
                    $response = logout();
                    echo json_encode($response);
                    break;
                    default:
                    echo json_encode(['message' => 'Action non définie']);
                    break;
                }
        } else {
            echo json_encode(['message' => 'Paramètre action manquant']);
        }
        break;

    case 'POST':
        if (isset($_POST['action'])) {
            switch ($_POST['action']) {
                case 'addChauffeur':
                    $response = addChauffeur($conn, $_POST['nom'], $_POST['email'], $_POST['mot_de_passe']);
                    echo json_encode($response);
                    break;
                case 'addVehicule':
                    $response = addVehicule($conn, $_POST['marque'], $_POST['modele'], $_POST['immatriculation']);
                    echo json_encode($response);
                    break;
                case 'addEntretien':
                    $response = addEntretien($conn, $_POST['type'], $_POST['date'], $_POST['vehicule_id'], $_POST['chauffeur_id']);
                    echo json_encode($response);
                    break;
                case 'addSuivi':
                    $response = addSuivi($conn, $_POST['entretien_id'], $_POST['kilometrage'], $_POST['carburant'], $_POST['photo_carburant']);
                    echo json_encode($response);
                    break;
                case 'addNettoyage':
                    $response = addNettoyage($conn, $_POST['entretien_id'], $_POST['photo_avant'], $_POST['photo_apres']);
                    echo json_encode($response);
                    break;
                case 'addCarburant':
                    $response = addCarburant($conn, $_POST['entretien_id'], $_POST['montant'], $_POST['litres'], $_POST['facture']);
                    echo json_encode($response);
                    break;
                case 'login':
                    $response = login($conn, $_POST['email'], $_POST['mot_de_passe']);
                    echo json_encode($response);
                    break;
                default:
                    echo json_encode(['message' => 'Action non définie']);
                    break;
            }
        } else {
            echo json_encode(['message' => 'Paramètre action manquant']);
        }
        break;

    default:
        echo json_encode(['message' => 'Méthode non supportée']);
        break;
}
?>
