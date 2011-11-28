
function init() {
	console.log("INIT");

	MochiKit.Signal.connect("doEncrypt", 'onclick', doEncrypt);
	MochiKit.Signal.connect("doDecrypt", 'onclick', doDecrypt);

	Clipperz.Crypto.PRNG.defaultRandomGenerator().fastEntropyAccumulationForTestingPurpose();
}


function doEncrypt() {
	var	key;
	var	value;

	key =	MochiKit.DOM.getElement('password').value;
	value =	MochiKit.DOM.getElement('plaintext').value;

	encrypt(key, value, MochiKit.DOM.getElement('encryptedtext'));
}

function doDecrypt() {
	var	key;
	var	value;

	key =	MochiKit.DOM.getElement('password').value;
	value =	MochiKit.DOM.getElement('encryptedtext').value;

	decrypt(key, value, MochiKit.DOM.getElement('plaintext'));
}

function encrypt(aKey, aValue, aTextArea) {
	var key, value;
	var	prng;
	var deferredResult;

	key = Clipperz.Crypto.SHA.sha_d256(new Clipperz.ByteArray(aKey));
	value = new Clipperz.ByteArray(aValue);
	prng = Clipperz.Crypto.PRNG.defaultRandomGenerator();

	deferredResult = new Clipperz.Async.Deferred("encrypt", {trace: true});
	deferredResult.addCallback(MochiKit.Base.method(prng, 'deferredEntropyCollection'));
	deferredResult.addCallback(Clipperz.Crypto.AES.deferredEncrypt, key, value);
	deferredResult.addCallback(MochiKit.Async.wait, 0.1);
	deferredResult.addCallback(function(aResult) {
		aTextArea.value = aResult.toBase64String();
	});
	deferredResult.addErrback(function(anError) {
		aTextArea.value = "ERROR";
	})

	deferredResult.callback();
}

function decrypt(aKey, aValue, aTextArea) {
	var key, value;
	var	prng;
	var deferredResult;

	key = Clipperz.Crypto.SHA.sha_d256(new Clipperz.ByteArray(aKey));
	value = new Clipperz.ByteArray().appendBase64String(aValue);
	prng = Clipperz.Crypto.PRNG.defaultRandomGenerator();

	deferredResult = new Clipperz.Async.Deferred("encrypt", {trace: true});
	deferredResult.addCallback(MochiKit.Base.method(prng, 'deferredEntropyCollection'));
	deferredResult.addCallback(Clipperz.Crypto.AES.deferredDecrypt, key, value);
	deferredResult.addCallback(MochiKit.Async.wait, 0.1);
	deferredResult.addCallback(function(aResult) {
		aTextArea.value = aResult.asString();
	});
	deferredResult.addErrback(function(anError) {
		aTextArea.value = "ERROR";
	})

	deferredResult.callback();
}

MochiKit.DOM.addLoadEvent(init);
