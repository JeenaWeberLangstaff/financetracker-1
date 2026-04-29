<?php
    require_once 'includes/database-connection.php';
    require_once 'includes/session.php';

    // Already logged in — go straight to dashboard
    if ($logged_in) {
        header('Location: index.php');
        exit;
    }

    // ========== CSRF TOKEN GENERATION ==========
    // Create a CSRF token if one doesn't exist in the session
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));  // Generate 64-character random token
    }

    $error = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        
        // ========== CSRF TOKEN VALIDATION ==========
        // Verify that the CSRF token in the form matches the one in the session
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = 'Invalid request. Please try again.';
        } else {
            
            $email = trim($_POST['email'] ?? '');
            $phone = trim($_POST['phone'] ?? '');
            
            $user = authenticate($pdo, $email, $phone);

            if ($user) {
                login($user);
                // Regenerate session ID to prevent session fixation attacks
                session_regenerate_id(true);
                header('Location: index.php');
                exit;
            } else {
                $error = 'Invalid email or phone number.';
            }
        }
    }

    require_once 'includes/header.php';
?>

<div class="login-container animate-bottom">
    <h1>Log In</h1>
    <hr>

    <?php if ($error): ?>
        <div class="login-error" style="display:block">
            <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>


    <form method="POST" action="login.php" class="login-form">

        <!-- ========== CSRF TOKEN FIELD ========== -->
        <!-- This hidden field prevents cross-site request forgery attacks -->
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email"
                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                   placeholder="you@email.com" required>
        </div>

        <div class="form-group">
            <label for="phone">Phone Number:</label>
            <!-- Changed from type="password" to type="tel" since this is a phone number, not a password -->
            <input type="tel" id="phone" name="phone"
                   value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>"
                   placeholder="123456789" required>
        </div>

        <div class="form-group">
            <input type="submit" value="Log In" class="submit-btn">
        </div>

    </form>
</div>

<?php require_once 'includes/footer.php'; ?>
