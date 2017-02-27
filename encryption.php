
<?php

  // validation of password, length of the password

  $password = filter_input(INPUT_POST, 'password');
  if (!$password || mb_strlen($password) < 8) {
    throw new Exception('Password must contain more than 8 characters!');
  }

  // real shit here, how to hash a password in fucking php

  $passwordhash = password_hash(
    $password,
    PASSWORD_DEFAULT,
    ['cost' => 12]
  );

 ?>



 <?php
session_start();
try {
// Get email address from request body
$email = filter_input(INPUT_POST, 'email');

// Get password from request body
$password = filter_input(INPUT_POST, 'password');

// Find account with email address (THIS IS PSUEDO-CODE)
$user = User::findByEmail($email);

// Verify password with account password hash
if (password_verify($password, $user->password_hash) === false) {
throw new Exception('Invalid password');
// Re-hash password if necessary (see note below)
              $user->password_hash,
              $currentHashAlgorithm,
              $currentHashOptions
);
if ($passwordNeedsRehash === true) {
              // Save new password hash (THIS IS PSUEDO-CODE)
              $user->password_hash = password_hash(
                  $password,
                  $currentHashAlgorithm,
                  $currentHashOptions
              );
              $user->save();
// Save login status to session
     $_SESSION['user_logged_in'] = 'yes';
     $_SESSION['user_email'] = $email;

// Redirect to profile page
    header('HTTP/1.1 302 Redirect');
    header('Location: /user-profile.php');
 } catch (Exception $e) {
    header('HTTP/1.1 401 Unauthorized');
    echo $e->getMessage();
 }
