<?php
include 'main.php';
// Save the email templates
if (isset($_POST['activation_email_template'])) {
    file_put_contents('../activation-email-template.html', $_POST['activation_email_template']);
    header('Location: emailtemplate.php?success_msg=1');
    exit;
}
if (isset($_POST['twofactor_email_template'])) {
    file_put_contents('../twofactor.html', $_POST['twofactor_email_template']);
    header('Location: emailtemplate.php?success_msg=1');
    exit;
}
if (isset($_POST['resetpass_email_template'])) {
    file_put_contents('../resetpass-email-template.html', $_POST['resetpass_email_template']);
    header('Location: emailtemplate.php?success_msg=1');
    exit;
}
// Read the activation email template HTML file
if (file_exists('../activation-email-template.html')) {
    $activation_email_template = file_get_contents('../activation-email-template.html');
}
// Read the two-factor email template
if (file_exists('../twofactor.html')) {
    $twofactor_email_template = file_get_contents('../twofactor.html');
}
// Read the reset password email template HTML file
if (file_exists('../resetpass-email-template.html')) {
    $resetpass_email_template = file_get_contents('../resetpass-email-template.html');
}
// Handle success messages
if (isset($_GET['success_msg'])) {
    if ($_GET['success_msg'] == 1) {
        $success_msg = 'Email template updated successfully!';
    }
}
?>
<?=template_admin_header('Email Template', 'emailtemplate')?>

<form action="" method="post" enctype="multipart/form-data">

    <div class="content-title responsive-flex-wrap responsive-pad-bot-3">
        <h2 class="responsive-width-100">Email Templates</h2>
        <input type="submit" name="submit" value="Save" class="btn">
    </div>

    <?php if (isset($success_msg)): ?>
    <div class="msg success">
        <i class="fas fa-check-circle"></i>
        <p><?=$success_msg?></p>
        <i class="fas fa-times"></i>
    </div>
    <?php endif; ?>

    <div class="content-block">

        <div class="form responsive-width-100">

            <?php if (isset($activation_email_template)): ?>
            <label for="activation_email_template">Activation Email Template</label>
            <textarea id="activation_email_template" name="activation_email_template"><?=$activation_email_template?></textarea>
            <?php endif; ?>

            <?php if (isset($twofactor_email_template)): ?>
            <label for="twofactor_email_template">Two-factor Email Template</label>
            <textarea id="twofactor_email_template" name="twofactor_email_template"><?=$twofactor_email_template?></textarea>
            <?php endif; ?>

            <?php if (isset($resetpass_email_template)): ?>
            <label for="resetpass_email_template">Reset Password Email Template</label>
            <textarea id="resetpass_email_template" name="resetpass_email_template"><?=$resetpass_email_template?></textarea>
            <?php endif; ?>

        </div>

    </div>

</form>

<?=template_admin_footer()?>