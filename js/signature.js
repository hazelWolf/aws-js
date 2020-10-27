/* ####################### SigV4 ####################### */
function Sign() {
    let date = new Date();
    longDate = amzLongDate(date);
    shortDate = amzShortDate(date);
    pathname = "/test.txt";
    host = "examplebucket.s3.amazonaws.com";
    //getSignatureKey('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20120215', 'us-east-1', 'iam')
   var canonical = canonicalRequest(pathname, host, date);
    console.log(canonical);
    var toSign = requestToSign(canonical, date);
    console.log(toSign);
    var signature = Signature(toSign, date);
    console.log(signature);
    var auth = "AWS4-HMAC-SHA256 Credential=" + "AKIAIOSFODNN7EXAMPLE" + "/" + shortDate + "/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-date;x-amz-content-sha256,Signature=" + signature;
}
var canonicalRequest = function(pathname, host, date) {
    return "GET" + '\n' + pathname + '\n' + "" + '\nhost:' + host + '\nrange:bytes=0-9\n' + ("x-amz-content-sha256:" + this.hashString("")) + '\n' + ('x-amz-date:' + longDate + '\n\n') + ('host;range;x-amz-content-sha256;x-amz-date\n') + this.hashString("");
  }

var requestToSign = function(cRequest,date) {
    return 'AWS4-HMAC-SHA256\n' + longDate + '\n' + shortDate + '/' + 'us-east-1' + '/s3/aws4_request\n' + this.hashString(cRequest);
  }

var Signature = function(toSign, date) {
    return this.hmac(this.hmac(this.hmac(this.hmac(this.hmac('AWS4' + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", this.amzShortDate(date)), 'us-east-1'), 's3'), 'aws4_request'), toSign).toString();
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
    return "20130524T000000Z";
  }
  Sign();