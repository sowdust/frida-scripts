/*

	Print sqlcipher properties
	can be used to print queries, db key, encryption type etc...
	written by sowdust & inode

	https://github.com/sqlcipher/sqlcipher/blob/master/src/crypto_impl.c




	// To retrieve more information about adopted algorithms (hmac and kdf)
	// it is possible to inspect the following structure within memory. 
	// To do so it is possible to look at the calling parameters of the function
	// that implements the structure (i.e.: sqlcipher_openssl_setup).
	// This procedure cannot be fully automated: the function is not directly callable with frida

	// https://github.com/sqlcipher/sqlcipher/blob/27d58453c6e56c3dd85e02bca379161bc69c746a/src/sqlcipher.h
	typedef struct {
	  int (*activate)(void *ctx);
	  int (*deactivate)(void *ctx);
	  const char* (*get_provider_name)(void *ctx);
	  int (*add_random)(void *ctx, void *buffer, int length);
	  int (*random)(void *ctx, void *buffer, int length);
	  int (*hmac)(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out);
	  int (*kdf)(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key);
	  int (*cipher)(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out);
	  const char* (*get_cipher)(void *ctx);
	  int (*get_key_sz)(void *ctx);
	  int (*get_iv_sz)(void *ctx);
	  int (*get_block_sz)(void *ctx);
	  int (*get_hmac_sz)(void *ctx, int algorithm);
	  int (*ctx_copy)(void *target_ctx, void *source_ctx);
	  int (*ctx_cmp)(void *c1, void *c2);
	  int (*ctx_init)(void **ctx);
	  int (*ctx_free)(void **ctx);
	  int (*fips_status)(void *ctx);
	  const char* (*get_provider_version)(void *ctx);
	} sqlcipher_provider;

	// get cipher provider version
    var libsqlcipher_sqlcipher_get_provider= Module.findExportByName(sqlcipher_module,'sqlcipher_get_provider');
	var sqlcipher_get_provider = new NativeFunction(libsqlcipher_sqlcipher_get_provider, 'pointer', ['pointer']);
	var provider = sqlcipher_get_provider(ctx);
	console.log(hexdump(provider, {
        offset: 0,
        length: 200,
        header: true,
        ansi: true
  	}));

*/


var verbose = true;
var colors = true;
var print_debug = false;
var print_queries = true;
var sqlcipher_module = 'libsqlcipher.so';
// not always working
var exec_pragma_queries = false;

var get_database_info;
var print_database_info;
var execute_pragma_query;

var ctx;
var ascii_pass;
var ascii_pass_len;
var db_path;
var raw_key;
var page_size;
var kdf_iter;
var cipher_provider;
var use_hmac;
var provider_version;
var store_pass;
var db_ref;
var sqlcipher_version;
var cipher_kdf_algorithm;
var cipher_hmac_algorithm;

var sqlite3_prepare_v2
var sqlite3_step
var sqlite3_column_text
var sqlite3_errormsg
var get_raw_key
var sqlcipher_codec_ctx_get_pagesize 
var sqlcipher_codec_ctx_get_kdf_iter
var sqlcipher_codec_get_cipher_provider
var sqlcipher_codec_get_provider_version
var sqlcipher_codec_ctx_get_use_hmac

var pragma_queries = [
	'PRAGMA cipher_fips_status;',
	'PRAGMA cipher_store_pass;',
	'PRAGMA cipher_profile;',
	'PRAGMA cipher_add_random;',
	'PRAGMA cipher_migrate;',
	'PRAGMA cipher_provider;',
	'PRAGMA cipher_provider_version;',
	'PRAGMA cipher_version;',
	'PRAGMA cipher;',
	'PRAGMA cipher_default_kdf_iter;',
	'PRAGMA cipher_default_kdf_iter;',
	'PRAGMA kdf_iter;',
	'PRAGMA fast_kdf_iter;',
	'PRAGMA cipher_page_size;',
	'PRAGMA cipher_default_page_size;',
	'PRAGMA cipher_default_use_hmac;',
	'PRAGMA cipher_use_hmac;',
	'PRAGMA cipher_hmac_pgno;',
	'PRAGMA cipher_hmac_salt_mask;',
	'PRAGMA cipher_plaintext_header_size;',
	'PRAGMA cipher_default_plaintext_header_size;',
	'PRAGMA cipher_salt;',
	'PRAGMA cipher_hmac_algorithm;',
	'PRAGMA cipher_default_hmac_algorithm;',
	'PRAGMA cipher_kdf_algorithm;',
	'PRAGMA cipher_default_kdf_algorithm;',
	'PRAGMA cipher_compatibility;',
	'PRAGMA cipher_default_compatibility;',
	'PRAGMA cipher_memory_security;',
	'PRAGMA cipher_settings;',
	'PRAGMA cipher_default_settings;',
	'PRAGMA cipher_integrity_check;'
]

function stampa(m) {
	if(verbose && colors) {
		console.log("\x1b[91m[Log] " + m + "\x1b[0m");
	}else if(verbose) {
		console.log('[Log] ' + m);
	}
}

function debug(m) {
	if(print_debug && colors) {
		console.log("\x1b[37m[Debug] "+ m + "\x1b[0m");
	}else if(print_debug) {
		console.log('[Debug] ' + m);
	}
}

var stringToByteArray = function(query) {
	var bytes = [];
    for (var i = 0; i < query.length; ++i) {
        bytes.push(query.charCodeAt(i));
    }	
    bytes.push(0x0);
    return bytes;
}

print_database_info = function() {

	console.log('-'.repeat(78))
	console.log(' '.repeat(32) + '\x1b[1mDATABASE INFO\x1b[0m    ')
	console.log('-'.repeat(78))	
	console.log('\x1b[1mDatabase path:\x1b[0m    ' + db_path);
	console.log('\x1b[1mSQL Cipher v.:\x1b[0m    ' + sqlcipher_version);
	console.log('\x1b[1mPage size:\x1b[0m        ' + page_size);
	console.log('\x1b[1mKDF Iterations:\x1b[0m   ' + kdf_iter);
	console.log('\x1b[1mCipher Provider:\x1b[0m  ' + cipher_provider);
	console.log('\x1b[1mProvider Version:\x1b[0m ' + provider_version);
	console.log('\x1b[1mUse HMAC:\x1b[0m         ' + use_hmac);
	if(cipher_hmac_algorithm != null && cipher_hmac_algorithm != 'undefined'){
		console.log('\x1b[1mHMAC algorithm:\x1b[0m   ' + cipher_hmac_algorithm);
	}
	if(cipher_kdf_algorithm != null && cipher_kdf_algorithm != 'undefined'){
		console.log('\x1b[1mKDF algorithm:\x1b[0m    ' + cipher_hmac_algorithm);
	}
	if(sqlcipher_version != null && sqlcipher_version != 'undefined'){
		console.log('\x1b[1mKDF Cipher v.:\x1b[0m    ' + cipher_hmac_algorithm);
	}

	console.log('\x1b[1mStore password:\x1b[0m   ' + store_pass);
	console.log('\x1b[1mAscii key:\x1b[0m        ' + ascii_pass);
	console.log('\x1b[1mRaw Key:\x1b[0m          ' + raw_key);
	console.log('-'.repeat(78))	
	
	return;
}

get_database_info = function () {
	// hooked by the "sqlcipher_activate"
	try{
		debug('[*] Trying to get database information ...')
		// get raw key
	    var key = Memory.alloc(200);
	    var nKey = Memory.alloc(200);
	    get_raw_key(ctx,key,nKey);
	    var raw_key_len = parseInt(Memory.readPointer(nKey));
	    var raw_key_t = Memory.readCString(Memory.readPointer(key),raw_key_len);
	    if(raw_key_t != 'undefined' && raw_key_t != null) {
	    	raw_key = raw_key_t;
	    	stampa(raw_key);
	    }    
	    // get page size
	    var page_size_t = parseInt(sqlcipher_codec_ctx_get_pagesize(ctx));
	    if(page_size_t > 0) {
	    	page_size = page_size_t;
	    	stampa('Page size: ' + page_size);
	    }
	    // get kdf iterations
	    var kdf_iter_t = parseInt(sqlcipher_codec_ctx_get_kdf_iter(ctx));
	    if(kdf_iter_t > 0) { 
	    	kdf_iter = kdf_iter_t;
	    	stampa('KDF Iterations: ' + kdf_iter);
		}
	    // get cipher provider
		var cipher_provider_t = Memory.readCString(sqlcipher_codec_get_cipher_provider(ctx));
		if(cipher_provider_t != 'undefined' && cipher_provider_t != null) {
	    	cipher_provider = cipher_provider_t;
	    	stampa(cipher_provider);
	    }
		// get cipher provider version
		var provider_version_t = Memory.readCString(sqlcipher_codec_get_provider_version(ctx));
		if(provider_version_t != 'undefined' && provider_version_t != null) {
	    	provider_version = provider_version_t;
	    	stampa(provider_version);
	    }
		// get use hmac
	    use_hmac = sqlcipher_codec_ctx_get_use_hmac(ctx);
	    stampa('USE HMAC: ' + use_hmac);

	    //sqlcipher_version = execute_pragma_query('PRAGMA cipher_version;');
	    // cipher_hmac_algorithm = execute_pragma_query('PRAGMA cipher_hmac_algorithm;');
	    // cipher_kdf_algorithm = execute_pragma_query('PRAGMA cipher_kdf_algorithm;');

	    // execute pragma keys
	    if(exec_pragma_queries) {
		    pragma_queries.forEach(execute_pragma_query);
		}

	}catch(err) {

		debug('[!] Error while getting database info.');
		debug(err);
		if(err.message.startsWith('access violation accessing')) {
			debug('Maybe the database is still encrypted?');
		}
		if(err.message.startsWith('invalid argument value')) {
			debug('Maybe the database is not open yet - or has been closed');
		}
	}
}

var execute_pragma_query = function(query_text) {

	var res = Memory.alloc(32);
	var query = query_text;
	var bytes = stringToByteArray(query);
	var query_bytes = Memory.alloc(500);
    Memory.writeByteArray(query_bytes, bytes);
    var pzTail = Memory.alloc(32);
    try {
		var cipher_version = sqlite3_prepare_v2(db_ref,query_bytes,500,res,pzTail);

		if(cipher_version != 0) {
			console.log("[!] Query error");
			var error = sqlite3_errormsg(db_ref);
			var err = Memory.readCString(error);
			console.log(err);
			return -1;

		} else {
			var result = Memory.readPointer(res);
			var sqlite3_step_res = sqlite3_step(result);
			var text = sqlite3_column_text(result,0)
			var res = Memory.readCString(ptr(text));
			stampa(query_text.replace('PRAGMA','').replace(';','') + ': ' + res);
			return res;
		}
	}catch(err) {
		console.log("[!] Errore nell'esecuzione della query " + query_text);
		console.log(err);
	}
}


Java.perform(function() {

	var awaitForCondition = function(callback) {
	    var int = setInterval(function() {
	        if (Module.findExportByName(sqlcipher_module, 'sqlite3_open')) {
	            clearInterval(int);
	            callback();
	            return;
	        }
	    }, 0);
	}
	function hook() {

		// sqlite3_prepare_v2
		var libsqlcipher_sqlite3_prepare_v2 = Module.findExportByName(sqlcipher_module,'sqlite3_prepare_v2');
		sqlite3_prepare_v2 = new NativeFunction(libsqlcipher_sqlite3_prepare_v2, 'int', ['pointer','pointer','int','pointer','pointer']);
		// sqlite3_step
		var libsqlcipher_sqlite3_step = Module.findExportByName(sqlcipher_module,'sqlite3_step');
		sqlite3_step = new NativeFunction(libsqlcipher_sqlite3_step, 'int', ['pointer']);
		// sqlite3_column_text
		var libsqlcipher_sqlite3_column_text = Module.findExportByName(sqlcipher_module,'sqlite3_column_text');
		sqlite3_column_text = new NativeFunction(libsqlcipher_sqlite3_column_text, 'pointer', ['pointer','int']);
		// sqlite3_errmsg
		var libsqlcipher_sqlite3_errormsg = Module.findExportByName(sqlcipher_module,'sqlite3_errmsg');
		sqlite3_errormsg = new NativeFunction(libsqlcipher_sqlite3_errormsg, 'pointer', ['pointer']);
		// sqlcipher_codec_get_keyspec
	    var libsqlcipher_sqlcipher_codec_get_keyspec = Module.findExportByName(sqlcipher_module,'sqlcipher_codec_get_keyspec');
	    get_raw_key = new NativeFunction(libsqlcipher_sqlcipher_codec_get_keyspec, 'void', ['pointer','pointer','pointer']);
	    // sqlcipher_codec_ctx_get_pagesize
	    var libsqlcipher_sqlcipher_codec_ctx_get_pagesize = Module.findExportByName(sqlcipher_module,'sqlcipher_codec_ctx_get_pagesize');
	    sqlcipher_codec_ctx_get_pagesize = new NativeFunction(libsqlcipher_sqlcipher_codec_ctx_get_pagesize, 'int', ['pointer']);
	    // sqlcipher_codec_ctx_get_kdf_iter
	    var libsqlcipher_sqlcipher_codec_ctx_get_kdf_iter = Module.findExportByName(sqlcipher_module,'sqlcipher_codec_ctx_get_kdf_iter');
	    sqlcipher_codec_ctx_get_kdf_iter = new NativeFunction(libsqlcipher_sqlcipher_codec_ctx_get_kdf_iter, 'int', ['pointer']);
	    // sqlcipher_codec_get_cipher_provider
	    var libsqlcipher_sqlcipher_codec_get_cipher_provider = Module.findExportByName(sqlcipher_module,'sqlcipher_codec_get_cipher_provider');
		sqlcipher_codec_get_cipher_provider = new NativeFunction(libsqlcipher_sqlcipher_codec_get_cipher_provider, 'pointer', ['pointer']);
		// sqlcipher_codec_get_provider_version
		var libsqlcipher_sqlcipher_codec_get_provider_version = Module.findExportByName(sqlcipher_module,'sqlcipher_codec_get_provider_version');
		sqlcipher_codec_get_provider_version = new NativeFunction(libsqlcipher_sqlcipher_codec_get_provider_version, 'pointer', ['pointer']);	
		// sqlcipher_codec_ctx_get_use_hmac
	    var libsqlcipher_sqlcipher_codec_ctx_get_use_hmac = Module.findExportByName(sqlcipher_module,'sqlcipher_codec_ctx_get_use_hmac');
	    sqlcipher_codec_ctx_get_use_hmac = new NativeFunction(libsqlcipher_sqlcipher_codec_ctx_get_use_hmac, 'int', ['pointer']);

		// save ctx reference to a global variable
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlcipher_codec_ctx_set_pass'),{
		    onEnter: function(args) {
		        ctx = ptr(args[0]);
		        get_database_info();
		    }
		});

		// save ctx reference to a global variable
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlcipher_free'),{
		    onEnter: function(args) {
		        //get_database_info();
		    }
		});

		// get db path from the "open" functions
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlcipher_activate'),{
		    onEnter: function(args) {
		    	get_database_info();
		    }
		});

		// get db path from the "open" functions
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlcipher_codec_get_store_pass'),{
		    onEnter: function(args) {
		    	store_pass = parseInt(args[0]);
		    }
		});

		// get db path from the "open" functions
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_open'),{
		    onEnter: function(args) {
		    	db_path = Memory.readCString(args[0]);
		    	stampa('DB Path: ' + db_path);
		    }
		});
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_open16'),{
		    onEnter: function(args) {
		    	db_path = Memory.readCString(args[0]);
		    	stampa('DB Path: ' + db_path);
		    }
		});
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_open_v2'),{
		    onEnter: function(args) {
		    	db_path = Memory.readCString(args[0]);
		    	stampa('DB Path: ' + db_path);
		    }
		});

		// get the ascii key from the "key" functions
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_key'),{

		    onEnter: function(args) {
		    	ascii_pass_len = parseInt(args[2]);
		    	ascii_pass = Memory.readCString(args[1],ascii_pass_len);   
		    	if(ascii_pass.length < ascii_pass_len) {
		    		ascii_pass += '-TRUNCATED - see hexdump';
		    		console.log(hexdump(ptr(args[1]), {
			            offset: 0,
			            length: ascii_pass_len,
			            header: true,
			            ansi: true
			      	}));
		    	}
		    	stampa('Ascii Password: ' + ascii_pass);
		    	stampa('Ascii Password Length: ' + ascii_pass_len);
		    }
		});
		Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_key_v2'),{

		    onEnter: function(args) {
		    	ascii_pass_len = parseInt(args[2]);
		    	ascii_pass = Memory.readCString(args[1],ascii_pass_len);   
		    	if(ascii_pass.length < ascii_pass_len) {
		    		ascii_pass += '-TRUNCATED - see hexdump';
		    		console.log(hexdump(ptr(args[1]), {
			            offset: 0,
			            length: ascii_pass_len,
			            header: true,
			            ansi: true
			      	}));
		    	}
		    	stampa('Ascii Password: ' + ascii_pass);
		    	stampa('Ascii Password Length: ' + ascii_pass_len);

		    	print_database_info();
		    }
		});

		if(print_queries) {

		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_exec'),{
		        onEnter: function(args) {
		            console.log('sqlite3_exec: ' + Memory.readCString(args[1]));
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_expanded_sql'),{
		        onEnter: function(args) {
		            console.log('sqlite3_expanded_sql: ' + Memory.readCString(args[1]));
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_prepare'),{
		        onEnter: function(args) {
		            db_ref = args[0];
		            console.log('sqlite3_prepare: ' + Memory.readCString(args[1]));            
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_prepare16'),{
		        onEnter: function(args) {
		            db_ref = args[0];
		            console.log('sqlite3_prepare16: ' + Memory.readUtf16String(args[1]));            
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_prepare16_v2'),{
		        onEnter: function(args) {
		        	console.log('sqlite3_prepare16_v2: ' + Memory.readUtf16String(args[1])); 
		            db_ref = args[0];
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_prepare16_v3'),{
		        onEnter: function(args) {
		            console.log('sqlite3_prepare16_v3: ' + Memory.readUtf16String(args[1]));            
		            db_ref = args[0];
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_prepare_v2'),{
		        onEnter: function(args) {
		            console.log('sqlite3_prepare_v2: '+ Memory.readCString(args[1]));            
		            db_ref = args[0];
		        }
		    });
		    Interceptor.attach(Module.findExportByName(sqlcipher_module,'sqlite3_prepare_v3'),{
		        onEnter: function(args) {
		            db_ref = args[0];
		            console.log('sqlite3_prepare_v3: ' + Memory.readCString(args[1]));            
		        }
		    });
		}
	} awaitForCondition(hook);
});

