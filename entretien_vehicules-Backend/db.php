<?php
$host = "localhost"; // Votre hôte
$db_name = "entretien_vehicules"; // Remplacez par le nom de votre base
$username = "root"; // Votre nom d'utilisateur
$password = ""; // Votre mot de passe

try {
    $conn = new PDO("mysql:host=$host;dbname=$db_name", $username, $password);
    // Configure PDO pour gérer les erreurs
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $exception) {
    echo "Erreur de connexion : " . $exception->getMessage();
}
?>
