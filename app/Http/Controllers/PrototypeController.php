<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Session;

class PrototypeController extends Controller
{
     /**
     * Llave base
     *
     * @var string
     */
    private $key = null;
    
    /**
     * string
     *
     * @var string
     */
    private $StringEncrypted = null;
    
    /**
     * string
     *
     * @var string
     */
    private $StringDecrypted = null;
   
    protected static $Config_SSL = array(
        "digest_alg" => null,
        "private_key_bits" => 4096,
        "private_key_type" => OPENSSL_KEYTYPE_RSA
    );
      
    /**
     * string
     *
     * @var string
     */
    private $ResponseKey;
      

    /**
     * Show the form
     *
     * @param  void
     * @return \Illuminate\View\View
     */
    private function generateNewKey($method){
        $privkey = "";
        $newKey = "";
        $cnf = self::$Config_SSL;
        $cnf["digest_alg"] = $method;
        $newKey = openssl_pkey_new($cnf);
        // Get private and public key
        openssl_pkey_export($newKey, $privkey);
        $this->ResponseKey = openssl_pkey_get_details($newKey);
        $this->ResponseKey = trim($this->ResponseKey["key"], "-----BEGIN PUBLIC KEY-----");
        $this->ResponseKey = substr($this->ResponseKey, 0, -25);
        $this->key = trim($privkey, "-----BEGIN PRIVATE KEY-----");
        $this->key = substr($this->key, 0, -26);
    }

    /**
     * Show the form
     *
     * @param  void
     * @return \Illuminate\View\View
     */
    private function encryptString($keyPub, $encript){
        $encripted = "";
        $keyPub = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($keyPub, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
        openssl_public_encrypt($encript, $encripted, $keyPub);
        $this->StringEncrypted = base64_encode($encripted);
    }
 
    /**
     * Show the form
     *
     * @param  void
     * @return \Illuminate\View\View
     */
    private function decryptString($keyPriv, $encripted){
        $decrypted = "";
        $keyPriv = "-----BEGIN PRIVATE KEY-----\n" . wordwrap($keyPriv, 64, "\n", true) . "\n-----END PRIVATE KEY-----";
        openssl_private_decrypt(base64_decode($encripted), $decrypted, $keyPriv);
        $this->StringDecrypted = $decrypted;
    }
   
    /**
     * Show the form
     *
     * @param  void
     * @return \Illuminate\View\View
     */
    public function index(){
        return view('prototype.index');
    }

    /**
     * Show the form
     *
     * @param  void
     * @return \Illuminate\View\View
     */
    public function generateKey(Request $request){
        //1.- Validar si existen los parametros en el request
        //2.- Mostrar mensajes flash de los errores

        // Tareas el metodo y generar una LLAVE NUEVA
        //Validar
        try{
            $method = $request->input('method');
            if(empty($method) || $method ==""){
                Session::flash('flash_message_key', 'No se encuentra un método válido.');
            }else{
                $this->generateNewKey($method);
                Session::flash('flash_message_key', "Llave publica: ".$this->ResponseKey);
                Session::flash('flash_message_priavte_key', "Llave privada: ". $this->key);
            }
            return view('prototype.index');
        }catch(\Exception $error){
            Session::flash('flash_message_key', 'Se ha producido un error: '.$error);
            return view('prototype.index');
        }
        
    }

    
    /**
     * Show the form
     *
     * @param  Request
     * @return \Illuminate\View\View
     */
    public function encrypt(Request $request){
        //1.- Validar si existen los parametros en el request
        //2.- Mostrar mensajes flash de los errores

        // Tareas recibir una llave y una cadena 
        // La llave tendrá que ser la misma que la seteada como propiedad
        // La cadena puede ser encriptada con OPEN SSL solamente con AES de 128bits
        // Se tiene que generar otro formulario(view) para DESENCRIPTAR una cadena privamente encriptada
        //

        //validar
        
        try{
            $keyPub = $request->input('key');
            $encript = $request->input('encript');
            if(empty($keyPub) || $keyPub =="" || empty($encript) || $encript ==""){
                Session::flash('flash_message_encrypted', 'No se puede continuar sin la "Llave" o "Cadena".');
            }else{
                $this->encryptString($keyPub, $encript);
                Session::flash('flash_message_encrypted', "Texto encriptado: ".$this->StringEncrypted);
            }
            return view('prototype.index');
            //Logica de las tareas
        }catch(\Exception $error){
            Session::flash('flash_message_encrypted', 'Se ha producido un error: '.$error);
            return view('prototype.index');
        }
    }
    
    /**
     * Show the form
     *
     * @param  Request
     * @return \Illuminate\View\View
     */
    public function decrypt(Request $request)
    {
        //1.- Validar existen los parametros en el request
        //2.- Mostrar mensajes flash de los errores

        // Tareas recibir una llave y una cadena 
        // La llave tendrá que ser la misma que la seteada como propiedad
        // La cadena puede ser encriptada con OPEN SSL solamente con AES de 128bits
        // Se tiene que generar otro formulario(view) para DESENCRIPTAR una cadena privamente encriptada
        //

        //validar
        try{
            $keyPriv= $request->input('key');
            $encripted = $request->input('encript');
            if(empty($keyPriv) || $keyPriv =="" || empty($encripted) || $encripted ==""){
                Session::flash('flash_message_decrypted', 'No se puede continuar sin la "Llave" o "Cadena".');
            }else{
                $this->decryptString($keyPriv, $encripted);
                Session::flash('flash_message_decrypted', "Texto desencriptado: ".$this->StringDecrypted);
            }
            return view('prototype.index');
            //Logica de las tareas
        }catch(\Exception $error){
            //Control de mensajes
            Session::flash('flash_message_decrypted', 'Se ha producido un error: '.$error);
            return view('prototype.index');
        }
    }
}