

(function CognitoSignIn() {
    var config = config = {
    "username" : "",
    "password" : "",
    "clientId" : "",
    "userPoolId" : "",
    "identityPoolId" : "",
    "region" : "us-east-1",
    "bucket" : "",
    "key" : "sample.json"
}
    var poolData = {
        UserPoolId: config.userPoolId, // your user pool id here ''
        ClientId: config.clientId// your app client id here'
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    //------------------Authentication-------------------------
    var userData = {
        Username: config.username, // your username here
        Pool: userPool
    };
    var authenticationData = {
        Username: config.username, // your username here
        Password: config.password, // your password here
    };
    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
    cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            console.log(JSON.stringify(result));
            _idTok = result.getIdToken().getJwtToken()
            _accessTok = result.getAccessToken().getJwtToken()
            _refreshTok = result.getRefreshToken()
            getCognitoIdentityCredentials("us-east-1", "<user-pool-id>", result.getIdToken().getJwtToken(), "<identity-pool-id>")
        },
        onFailure: function (err) {
            console.log(JSON.stringify(err));
        }
    });
}());

function getCognitoIdentityCredentials(region, userPoolId, idToken, identityPoolId, result) {
    AWS.config.region = region;

    var loginMap = {};
    loginMap['cognito-idp.' + region + '.amazonaws.com/' + userPoolId] = idToken;

    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
        IdentityPoolId: identityPoolId,
        Logins: loginMap
    });

    AWS.config.credentials.clearCachedId();

    AWS.config.credentials.get(function (err) {
        if (err) {
            console.log(err.message);
        }
        else {
            console.log(AWS.config.credentials)
            access = AWS.config.credentials.accessKeyId;
            secret = AWS.config.credentials.secretAccessKey;
            session = AWS.config.credentials.sessionToken;
            console.log('AWS Access Key: ' + access);
            console.log('AWS Secret Key: ' + secret);
            console.log('AWS Session Token: ' + session);
            //getAWSS3BucketObjects();
            //GetObject();
            //Check();
            //PreSignPostURL({accessKeyId : access, secretAccessKey : secret,sessionToken: session,  region : "<region>", signatureVersion: 'v4',})
            //getSignatureKey(secret,new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '').substr(0, 17), "<region>","<service eg. S3>" )
            Sign("<url-to-sign>");
        }
    });
}

function getAWSS3BucketObjects() {
    var s3 = new AWS.S3({ signatureVersion: 'v2' });
    var params = {
        Bucket: config.bucket
    };
    var arrayofElements = [];
    var arrayofObjects = [];
    s3.listObjects(params, function (err, data) {
        if (err) console.log(err.message);
        else {
            console.log('');
            console.log('====== S3 Bucket Objects ======');
            data.Contents.forEach(element => {
                console.log(element.LastModified);
                console.log(new Date());
                console.log(Date.parse(element.LastModified))
                var diffMs = new Date() - Date.parse(element.LastModified)
                var diffDays = Math.floor(diffMs / 86400000); // days
                var diffHrs = Math.floor((diffMs % 86400000) / 3600000); // hours
                var diffMins = Math.round(((diffMs % 86400000) % 3600000) / 60000); // minutes
                console.log(element.Key, diffDays + " days" + diffHrs + " hrs" + diffMins + " mins");
                if (diffDays == 0 && diffHrs < 1 && diffMins < 30) {
                    if (arrayofElements.indexOf(element.Key) < 0) {
                        arrayofElements.push(element.Key);
                        var params = {
                            Bucket: config.bucket,
                            Key: element.Key
                        };
                        s3.getObject(params, function (err, data) {
                            // Handle any error and exit
                            if (err)
                                console.log(err);
                            else {
                                // No error happened
                                // Convert Body from a Buffer to a String

                                let objectData = data.Body.toString('utf-8'); // Use the encoding necessary
                                arrayofObjects.push(JSON.parse(objectData));
                            }
                        });
                    }
                    else {
                        console.log("exists");
                    }
                }
            });
            console.log(arrayofElements);
            console.log(arrayofObjects);
        }
    });
};

function GetObject() {
    var s3 = new AWS.S3({ signatureVersion: 'v2' });

    var params = {
        Bucket: config.bucket,
        Key: config.key
    };
    s3.getObject(params, function (err, data) {
        // Handle any error and exit
        if (err)
            console.log(err);
        else {
            // No error happened
            // Convert Body from a Buffer to a String

            let objectData = data.Body.toString('utf-8'); // Use the encoding necessary
            console.log(objectData);
            console.log(JSON.parse(objectData));
        }
    });
}


function PreSignURL(credentials) {
    var s3 = new AWS.S3(credentials);
    var params = { Bucket: config.bucket, Key: config.key, Expires: 600 };
    var presignedURL = s3.getSignedUrl('getObject', params)
    console.log("link is :: " + presignedURL)
    fetch(presignedURL)
        .then(
            function (response) {
                if (response.status !== 200) {
                    console.log('Looks like there was a problem. Status Code: ' +
                        response.status);
                    return;
                }

                // Examine the text in the response
                response.json().then(function (data) {
                    console.log(data);
                });
            }
        )
        .catch(function (err) {
            console.log('Fetch Error :-S', err);
        });
}

function PreSignPostURL(credentials) {
    var s3 = new AWS.S3(credentials);
    var params = { Bucket: config.bucket, Key: config.key };
    var url = s3.getSignedUrl('putObject', params)
    console.log(url);
    fetch(url, {
        method: 'PUT',
        body: "{'sample':'sample'}",
    });
    new Date().getDay
}

function logOut() {
    if (cognitoUser != null) {
        cognitoUser.signOut();
        console.log('Logged out!');
    }
}

var CheckExpiration = function (region, userPoolId, identityPoolId) {
    if (AWS.config.credentials.needsRefresh()) {
        cognitoUser.refreshSession(_refreshTok, (err, session) => {
            if (err) {
                console.log(err.message);
            }
            else {
                var loginMap = {};
                loginMap['cognito-idp.' + region + '.amazonaws.com/' + userPoolId] = session.getIdToken().getJwtToken();
                AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                    IdentityPoolId: identityPoolId,
                    Logins: loginMap
                });
                AWS.config.credentials.clearCachedId();
                AWS.config.credentials.refresh((err) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        console.log("TOKEN SUCCESSFULLY UPDATED");
                    }
                });
            }
        });
    }
    else {
        console.log("No refresh required");
    }
}
function Check() {
    CheckExpiration("us-east-1", "<user-pool-id>", "<identity-pool-id>");
}

var PreSignPut = function (accessKeyId, secretAccessKey, sessionToken, region, bucket, feedbackLink, id, count, gameObject, method) {
    AWS.config.update({ accessKeyId: Pointer_stringify(accessKeyId), secretAccessKey: Pointer_stringify(secretAccessKey), sessionToken: Pointer_stringify(sessionToken), region: Pointer_stringify(region) })
    var s3 = new AWS.S3({ signatureVersion: 'v4' });
    var urls = [];
    for (i = 0; i < count; i++) {
        var dt = new Date().getTime();
        var uuid = 'xx-5xx'.replace(/[xy]/g, function (c) {
            var r = (dt + Math.random() * 16) % 16 | 0;
            dt = Math.floor(dt / 16);
            arrayUUID.push((c == 'x' ? r : (r & 0x3 | 0x8)).toString(16));
        })
        var params = { Bucket: Pointer_stringify(bucket), Key: uuid + '.json', Expires: 1800, ContentType: "application/json" };
        var url = s3.getSignedUrl('putObject', params)
        urls.push(url);
    }
    for (i = 0; i < urls.length; i++) {
        var file = arrayUUID[i];
        var date = getQueryString("X-Amz-Date", urls[i]);
        var token = getQueryString("X-Amz-Security-Token", urls[i]);
        var sign = getQueryString("X-Amz-Signature", urls[i]);
        window.open(Pointer_stringify(feedbackLink) + "?i=" + Pointer_stringify(id) + "&b=" + Pointer_stringify(bucket) + "&f=" + file + "&d=" + date + "&s=" + token + "&si=" + sign, '_blank');
        window.focus();
    }
    unityInstance.SendMessage(go, m, "done");
}

/* ####################### SigV4 ####################### */
function Sign(url,) {
    let date = new Date();
    longDate = amzLongDate(date);
    shortDate = amzShortDate(date);
    let uri = url;
    let a = document.createElement('a');
    a.href = url;
    console.log(a.host);
    console.log(a.pathname);
    console.log(hashString(""));
   var canonical = canonicalRequest(a.pathname, a.host);
    console.log(canonical);
    var toSign = requestToSign(canonical, date);
    console.log(toSign);
    var signature = Signature(toSign, date);
    console.log(signature);
    var auth = "AWS4-HMAC-SHA256 Credential=" + access + "/" + shortDate + "/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature=" + signature;
    fetchData(url,auth,a.host,this.hashString(""), longDate)
}
var canonicalRequest = function(pathname, host) {
    return "GET" + '\n' + pathname + '\n' + "" + '\nhost:' + host + '\n' + ("x-amz-content-sha256:" + this.hashString("")) + '\n' + ('x-amz-date:' + longDate + '\nx-amz-security-token:' + session+ '\n\n') + ('host;x-amz-content-sha256;x-amz-date;x-amz-security-token\n') + this.hashString("");
  }

var requestToSign = function(cRequest) {
    return 'AWS4-HMAC-SHA256\n' + longDate + '\n' + shortDate + '/' + 'us-east-1' + '/s3/aws4_request\n' + this.hashString(cRequest);
  }

var Signature = function(toSign) {
    console.log(this.hmac(this.hmac(this.hmac(this.hmac('AWS4' + secret, shortDate), 'us-east-1'), 's3'), 'aws4_request'));
    console.log(toSign);
    return this.hmac(this.hmac(this.hmac(this.hmac(this.hmac('AWS4' + secret, shortDate), 'us-east-1'), 's3'), 'aws4_request'), toSign).toString();
  }
var hashString = function(str) {
    return CryptoJS.SHA256(str).toString();
  }

var hmac = function(key, data) {
    return CryptoJS.HmacSHA256(data, key);
  }

var   amzShortDate = function(date) {
    return this.amzLongDate(date).substr(0, 8);
  }

var amzLongDate = function(date) {
    return date.toISOString().replace(/[:\-]|\.\d{3}/g, '').substr(0, 17);
  }
function getSignatureKey(key, dateStamp, regionName, serviceName) {
    var data = [];
    for (var i = 0; i < ("AWS4" + key).length; i++) {
        data.push(("AWS4" + key).charCodeAt(i));
    }
    console.log(data.toString());
    var kDate = CryptoJS.HmacSHA256(dateStamp, "AWS4" + key);
    console.log(kDate.toString());
    var kRegion = CryptoJS.HmacSHA256(regionName, kDate);
    console.log(kRegion.toString());
    var kService = CryptoJS.HmacSHA256(serviceName, kRegion);
    console.log(kService.toString());
    var kSigning = CryptoJS.HmacSHA256("aws4_request", kService);
    console.log(kSigning.toString());
    return kSigning;
}

function fetchData(url, auth, host, content, date){
    var xhr = new XMLHttpRequest();
    xhr.open('GET',url);
    xhr.setRequestHeader("Authorization", auth);
    xhr.setRequestHeader("host", host);
    xhr.setRequestHeader("X-Amz-Content-Sha256", content);
    xhr.setRequestHeader("X-Amz-Date", date);
    xhr.setRequestHeader("X-Amz-Security-Token", session);
    xhr.onload = function () {
        this.status === 200 ? resolve() : reject(this.responseText);
    };
    xhr.send();
}