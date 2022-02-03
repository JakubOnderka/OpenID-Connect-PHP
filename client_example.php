<?php
/**
 * Copyright MITRE 2012
 * Copyright Jakub Onderka 2022
 *
 * OpenIDConnectClient for PHP
 * Author: Michael Jett <mjett@mitre.org>
 *         Jakub Onderka <jakub.onderka@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

require __DIR__ . '/vendor/autoload.php';

$oidc = new JakubOnderka\OpenIDConnectClient(
    'http://myproviderURL.com/',
    'ClientIDHere',
    'ClientSecretHere'
);

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
?>
<html>
<head>
    <title>Example OpenID Connect Client Use</title>
    <style>
        body {
            font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>
    <div>
        Hello <?= $name ?>
    </div>
</body>
</html>

