<?php
class EjyUtils{

    const KEY = "123si56";

    /**
     * 可加密一个或多个半角逗号分隔的字符串
     * @param $content
     * @return string
     */
    public static function encryptContent($content)
    {
        $content = explode(",",$content);
        foreach($content as &$c){
            $c = trim($c);
            if($c != null && $c != ""){
                $c = strtoupper(self::encrypt($c));
            }
        }
        return implode(",",$content);

    }
    /**
     * 可解密一个或多个半角逗号分隔的字符串
     * @param $content
     * @return string
     */
    public static function decryptContent($content)
    {
        $content = explode(",",$content);
        foreach($content as &$c){
            $c = trim($c);
            if($c != null && $c != ""){
                $c = self::decrypt($c);
            }
        }
        return implode(",",$content);
    }

    /**
     * 可加密单个字符串
     * @param $content
     * @return string
     */
    public static function encrypt($encrypt) {
        try{
            $key = substr(openssl_digest(openssl_digest(self::KEY, 'sha1', true), 'sha1', true), 0, 16);
            $iv = openssl_random_pseudo_bytes(0);
            $encrypted = openssl_encrypt($encrypt, 'AES-128-ECB',$key,OPENSSL_RAW_DATA,$iv);
            return bin2hex($encrypted);
        }catch(\Exception $e){
            return $encrypt;
        }
    }

    /**
     * 可解密单个字符串
     * @param $content
     * @return string
     */
    public static function decrypt($decrypt) {
        try{
            $key = substr(openssl_digest(openssl_digest(self::KEY, 'sha1', true), 'sha1', true), 0, 16);
            $decoded = hex2bin($decrypt);
            $iv = openssl_random_pseudo_bytes(0);
            return openssl_decrypt($decoded, 'AES-128-ECB',$key,OPENSSL_RAW_DATA,$iv);
        }catch(\Exception $e){
            return $decrypt;
        }
    }

    public static function makeSmsCode($length = 6){
        $codeSet = '1234567890';
        $codes = array();
        for ($i = 0; $i<$length; $i++) {
            $codes[$i] = $codeSet[mt_rand(0, strlen($codeSet)-1)];
        }
        return implode($codes);
    }

    public static function unicodeEncode($name)
    {
        $json = '{"str":"'.$name.'"}';
        $arr = json_decode($json,true);
        if(empty($arr)){
            return '';
        }
        return $arr['str'];
    }

    /**
     * 判断是否是https
     * @return bool
     */
    public static function isHttps(){
        if((array_key_exists('HTTPS', $_SERVER) && ($_SERVER['HTTPS'] === 'on' || $_SERVER['HTTPS'] === 1 || $_SERVER['HTTPS'] === 443))
            || (array_key_exists('HTTP_X_FORWARDED_PROTO', $_SERVER) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')){
            return TRUE;
        }
        return FALSE;
    }


    /**
     * 获取浏览器平台
     * @return int
     * IOS       1
     * IOS new       11
     * 安卓       2
     * 微信       3
     * aliapp      4
     * 其他浏览器  4
     */
    public static function clientOsType(){
        if(isset($_SERVER['HTTP_USER_AGENT'])){
            $user_agent = $_SERVER['HTTP_USER_AGENT'];
            $user_agent = strtolower($user_agent);
            if (strpos($user_agent, 'micromessenger')){
                return 3;
            }
            if(isset($_SERVER["HTTP_OSTYPE"])){
                $os_type = $_SERVER["HTTP_OSTYPE"];
                if( $os_type == 'Zhangjian'){
                    return 1;
                }
                if( $os_type == 'iOSejy'){
                    return 11;
                } // ios 新header信息 版本5.3.1
                if( $os_type == 'android'){
                    return 2;
                }
            }
            return 4;
        }
        return 0;
    }

}
