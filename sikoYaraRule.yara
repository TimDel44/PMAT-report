rule Yara_SikoMode{
    meta: 
        last_updated = "2022-01-12"
        author = "TimDel"
        description = "Yara rule for SikoMode2.0"
 
    strings:
        // Fill out identifying strings and other criteria
        $lang = "nim"
        $PE_magic_byte = "MZ"
        $password = "C:\\Users\\Public\\passwrd.txt" ascii
        $url = "http://cdn.altimiter.local/feed?post=" ascii
        $sus_function_houdini= "houdini__sikomode" ascii
        $sus_function_stealstuff ="stealStuff__sikomode" ascii
 
    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and
        ($url and $password) or ($sus_function_houdini and $sus_function_stealstuff) and $lang 

}