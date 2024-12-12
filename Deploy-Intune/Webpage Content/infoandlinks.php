<?php
include('config.php');
$sitename = "DeployIntune from EUC Toolbox";
$pagetitle = "DeployIntune Info and Links";
include "header.php";
?>

            <h2>Your tenant is configured and ready to use.  You can find some links and documentation below to get started.</h2>
                <p>Please note the Conditional Access policies have all been deployed, but left switched off.  These will need activating once you have tested them.</p>
                <p>We recommend using the What If button to test different scenarios.</p>
    
                <table class="styled-table">
                    <thead>
                        <tr>
                            <th style="width: 50%;">Document Type</th>
                            <th style="width: 50%;">Link</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style="width: 50%;">Breakglass accounts</td>
                            <td style="width: 50%;"><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Getting Started Guide</td>
                            <td style="width: 50%;"><a href="/documents/Getting-Started-Guide.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Tenant Documentation</td>
                            <td style="width: 50%;"><a href="/documents/Deployed-Policies.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Monitoring and Troubleshooting Guide</td>
                            <td style="width: 50%;"><a href="/documents/IntuneReportingandMonitoring.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Conditional Access</td>
                            <td style="width: 50%;"><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Windows Enrollment</td>
                            <td style="width: 50%;"><a href="/documents/Windows-Enrollment-Guide.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Setup Managed Google Play</td>
                            <td style="width: 50%;"><a href="https://www.cloudtekspace.com/post/connect-intune-with-managed-google-play-account" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Android Enrollment</td>
                            <td style="width: 50%;"><a href="/documents/Android-Enrollment-Guide.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Setup Apple Business Manager</td>
                            <td style="width: 50%;"><a href="https://support.apple.com/en-gb/guide/apple-business-manager/axm402206497/web" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Apple Business Manager Configuration in Intune</td>
                            <td style="width: 50%;"><a href="https://learn.microsoft.com/en-us/mem/intune/enrollment/device-enrollment-program-enroll-ios" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">Non-VPP macOS Enrollment</td>
                            <td style="width: 50%;"><a href="/documents/EnrolNonVPPMacOSDevice.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">VPP macOS Enrollment</td>
                            <td style="width: 50%;"><a href="/documents/EnrolVPPMacOSDevice.pdf" target="_blank">Link</a></td>
                        </tr>
                        <tr>
                            <td style="width: 50%;">iOS Enrollment</td>
                            <td style="width: 50%;"><a href="/documents/iOS-Enrollment-Guide.pdf" target="_blank">Link</a></td>
                        </tr>
                    </tbody>
                </table>
                <?php
include "footer.php";
?>