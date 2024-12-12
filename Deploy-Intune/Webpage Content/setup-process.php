<?php
/* This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://github.com/andrew-s-taylor/public/blob/main/LICENSE>.
 */
?>
<?php
include('config.php');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        // The form was submitted from index.php, continue processing

?>

<style type="text/css">
 .lds-ring {
  display: inline-block;
  position: relative;
  width: 100px;
  height: 100px;
  padding-top: 20px;
}

.lds-ring div {
  box-sizing: border-box;
  display: block;
  position: absolute;
  width: 64px;
  height: 64px;
  margin: 8px;
  border: 8px solid #d1d4da;
  border-radius: 50%;
  animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
  border-color: #d1d4da transparent transparent transparent;
}

.lds-ring div:nth-child(1) {
  animation-delay: -0.45s;
}

.lds-ring div:nth-child(2) {
  animation-delay: -0.3s;
}

.lds-ring div:nth-child(3) {
  animation-delay: -0.15s;
}

@keyframes lds-ring {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

 
.drop-container {
  position: relative;
  display: flex;
  gap: 10px;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  height: 200px;
  padding: 20px;
  border-radius: 10px;
  border: 2px dashed #555;
  color: #444;
  cursor: pointer;
  transition: background .2s ease-in-out, border .2s ease-in-out;
}

.drop-container:hover {
  background: #eee;
  border-color: #111;
}

.drop-container:hover .drop-title {
  color: #222;
}

.drop-title {
  color: #444;
  font-size: 20px;
  font-weight: bold;
  text-align: center;
  transition: color .2s ease-in-out;
}

input[type=file] {
  width: 350px;
  max-width: 100%;
  color: #444;
  padding: 5px;
  background: #fff;
  border-radius: 10px;
  border: 1px solid #555;
}

input[type=file]::file-selector-button {
  margin-right: 20px;
  border: none;
  background: #808080;
  padding: 10px 20px;
  border-radius: 10px;
  color: #fff;
  cursor: pointer;
  transition: background .2s ease-in-out;
}

input[type=file]::file-selector-button:hover {
  background: #EB5D2F;
}

.input-container {
  height: 50px;
  position: relative;
  width: 100%;
}

.ic1 {
  margin-top: 40px;
}

.ic2 {
  margin-top: 30px;
}

.input-container2 {
  height: 180px;
  position: relative;
  width: 100%;
  border-radius: 12px;
  border: 1px solid #dbdbdb;
  box-sizing: border-box;
}
.input-container3 {
  height: 100%;
  position: relative;
  width: 100%;
  border-radius: 12px;
  border: 1px solid #dbdbdb;
  box-sizing: border-box;
}

.ic3 {
  margin-top: 40px;
  padding-left:20px;
}

.input {
  background-color: #fff;
  border-radius: 12px;
  border: 1px solid #dbdbdb;
  box-sizing: border-box;
  color: #000;
  font-size: 18px;
  height: 100%;
  outline: 0;
  padding: 4px 20px 0;
  width: 100%;
}

.input:focus ~ .cut,
.input:not(:placeholder-shown) ~ .cut {
  transform: translateY(8px);
}

.placeholder {
  color: #65657b;
  font-family: sans-serif;
  left: 20px;
  line-height: 14px;
  pointer-events: none;
  position: absolute;
  transform-origin: 0 50%;
  transition: transform 200ms, color 200ms;
  top: 20px;
}

.placeholder2 {
  color: #65657b;
  font-family: sans-serif;
  left: 80px;
  line-height: 0px;
  pointer-events: none;
  position: absolute;
  transform-origin: 0 50%;
  transition: transform 200ms, color 200ms;
  top: 20px;
}

.input:focus ~ .placeholder,
.input:not(:placeholder-shown) ~ .placeholder {
  transform: translateY(-30px) translateX(10px) scale(0.75);
}

.input:not(:placeholder-shown) ~ .placeholder {
  color: #fff;
}

.profile-btn {
    display: inline-block;
    text-decoration: none;
    border: 0;
    cursor: pointer;
    color: #fff;
    background-color: #EB5D2F;
    margin: 0px 5px 0 0;
    padding: 10px 15px;
    border-radius: 14px;
    appearance: none;
    font-size: 14px;
    font-weight: 500;
  }
  
  .profile-btn:hover {
    background-color: #af4724;
  }


/* The switch - the box around the slider */
.switch {
  position: relative;
  display: inline-block;
  width: 60px;
  height: 34px;
}

/* Hide default HTML checkbox */
.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

/* The slider */
.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #ccc;
  -webkit-transition: .4s;
  transition: .4s;
}

.slider:before {
  position: absolute;
  content: "";
  height: 26px;
  width: 26px;
  left: 4px;
  bottom: 4px;
  background-color: white;
  -webkit-transition: .4s;
  transition: .4s;
}

input:checked + .slider {
  background-color: #EB5D2F;
}

input:focus + .slider {
  box-shadow: 0 0 1px #EB5D2F;
}

input:checked + .slider:before {
  -webkit-transform: translateX(26px);
  -ms-transform: translateX(26px);
  transform: translateX(26px);
}

/* Rounded sliders */
.slider.round {
  border-radius: 34px;
}

.slider.round:before {
  border-radius: 50%;
} 

.fcc-btn {
  background-color: #808080;
  color: #ffffff;
  padding: 15px 25px;
  text-decoration: none;
  font-size: 16px;
  border-radius: 10px;
  border: 2px solid #808080;
  box-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
}

.fcc-btn:hover {
  background-color: #EB5D2F;
}

.input:focus ~ .placeholder {
  color: #EB5D2F;
}

    </style>



<?php
$sitename = "DeployIntune from EUC Toolbox";
$pagetitle = "DeployIntune";
include "header.php";
?>

    <form action="process.php" enctype="multipart/form-data" method="post">
    <input id="tenant" name="tenant" class="input" type="hidden" value="<?php echo $tenant; ?>" />
    <input type="hidden" name="customerid" value="<?php echo $customerid; ?>" />
        <div class="form">
          <div class="logo">
          </div>
          <div class="title">Welcome</div>
            <div class="subtitle">Please complete the form for your deployment to start</div>
            <table class="styled-table">
              <tr>
                <td>
                  <div class="input-container ic1">
                    <input id="name" class="input" type="text" placeholder=" " name="name" />
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">Enter your company name to add a registry key</span>
                    </div>
                    <label for="name" class="placeholder">Company Name</label>
                  </div>
                </td>
                <td>
                  <div class="input-container ic1">
                    <input id="email" class="input" type="text" placeholder=" " name="email" />
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">Your email address to receive details on completion</span>
                    </div>
                    <label for="email" class="placeholder">Email Address</label>
                  </div>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="input-container ic2">
                    <input id="homepage" name="homepage" class="input" type="text" placeholder=" " />
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">Microsoft Edge Homepage</span>
                    </div>
                    <label for="homepage" class="placeholder">Homepage</label>
                  </div>
                </td>
                <td>
                  <div class="input-container ic2">
                    <label for="tenant" class="placeholder">Tenant ID</label>
                    <input id="tenant" name="tenant" class="input" type="text" placeholder=" " />

                  </div>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="input-container ic1">
                    <input id="prefix" name="prefix" class="input" type="text" placeholder=" " />
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">Prefix for policies and Entra groups</span>
                    </div>
                    <label for="prefix" class="placeholder">Prefix</label>
                  </div>
                </td>
                <td>
                  <label for="images" class="drop-container">
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">Desktop wallpaper in JPG or PNG format</span>
                    </div>
                    <span class="drop-title">Drop desktop wallpaper file here</span>
                    or
                    <input type="file" id="fileToUpload" name="fileToUpload" accept="image/*" required onchange="checkFileSize(this)">
                  </label>
                  <script>
                    function checkFileSize(input) {
                      if (input.files[0].size > 200000) {
                        alert("File size must not exceed 200KB.");
                        input.value = '';
                      }
                    }
                  </script>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="input-container ic1">
                    <label class="switch">
                      <input id="fresh" name="fresh" class="input" type="checkbox" placeholder=" " value="Yes" />
                      <span class="slider round"></span>
                    </label>
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">If this is a fresh environment, enable this box</span>
                    </div>
                    <label for="tenant" class="placeholder2">Fresh environment</label>
                  </div>
                </td>
                <td>
                  <div class="input-container ic1">
                    <label class="switch">
                      <input id="CAD" name="CAD" class="input" type="checkbox" placeholder=" " value="Yes" />
                      <span class="slider round"></span>
                    </label>
                    <div class="tooltip">
                      <img src="tooltip.png" alt="Information" width="20" height="20">
                      <span class="tooltiptext">If you do not have Conditional Access, enable this for further protection</span>
                    </div>
                    <label for="tenant" class="placeholder2">Deploy Conditional Access</label>
                  </div>
                </td>
              </tr>
              <tr>
                <td colspan="2" class="tableButton" align="center">
                    <button type="submit" class="profile-btn" id="submitBtn">Submit</button>
              </tr>
            </table>
            <script>
              document.getElementById('submitBtn').addEventListener('click', function(event) {
                var inputs = document.getElementsByTagName('input');
                for (var i = 0; i < inputs.length; i++) {
                  if (inputs[i].value.trim() === '' && inputs[i].type !== 'hidden') {
                    event.preventDefault();
                    alert('Please fill all the fields');
                    return;
                  }
                }
              });
            </script>
          </div>
                    </div>
                    </form>
                    <?php
include "footer.php";
?>

<?php
} else {
    // The request method is not POST, stop processing
    exit('Invalid request method');
}


?>