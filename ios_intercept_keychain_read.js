// Print values as they are extracted from the keychain

Interceptor.attach(Module.findExportByName("Security","SecItemCopyMatching"),
  {
    onEnter: function(args) {
        var arg1 = ObjC.Object(args[0]);
        console.log('[*] SecItemCopyMatching arg 1: ' + arg1.toString());
        this.val = args[1];
    },
    onLeave: function(retval) {
    	if(retval.toString() == '0x0') {
    		var result = new ObjC.Object(Memory.readPointer(this.val));
    		console.log('[*]' + result.toString());
    	}
    }
});