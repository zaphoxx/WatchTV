# WatchTV
Tool to extract TeamViewer encrypted passwords from Windows Registry.

        #################L   .###############u
        ##################N.@################ *
        ##################################### '>.n=L
        ###############################RR#### 'b"  9
        ###########################R#"  .#### @   .*
        ########################^   .e#######P   e"
        #####################R#    o########P   @
        ###################P" .e> 4#" '####F  .F
        #################R  .###& '#   ####  .#>
        #################b.o#####  #N  "##" ."'>
        #########################  ##N  "^ .# '>
        ############## "########R  ###&    ## '>
        ##############  E"##P^9#E  ####   8## '>
        ##############  E  "  9#F  ####k .### '>
        ##############  E     9#N  ########## '>
        ##############  E     9##.u########## '>
        ############## o"     9############## d
        **************#       ***************
        ManniTV

This is based on the blog post and scripts found here
<a href="https://whynotsecurity.com/blog/teamviewer/">https://whynotsecurity.com/blog/teamviewer/</a>.
This is my first powershell script. So if you have any remarks or 
suggestions on how this could be improved, don't hesitate to tell
me so!

Feel free to use this for legal purpose only (e.g. penetration tests, hack the box machines etc.). Do not use this tool for illegal purpose!

EXCLAIMER!
Please use this only on machines where you have the authorization and 
permission to use this for. It would be illegal to use this out in the 
wild on machines where you do not have the authorization to do so. So 
please don't!

    FileName: WatchTV.ps1
    Author: Manfred Heinz (@zaphoxx,@manniTV)
    Last Update: 26.03.2020
    Licens: GNU GPLv3
    Required Dependencies: None
    Optional Dependencies: None
    References:
        <a href="https://whynotsecurity.com/blog/teamviewer/">https://whynotsecurity.com/blog/teamviewer/</a>
        <a href="https://gist.github.com/ctigeek/2a56648b923d198a6e60">https://gist.github.com/ctigeek/2a56648b923d198a6e60</a>
    
    .SYNOPSIS
        The main purpose of this script is to retrieve TeamViewers encrypted
        passwords from the Windows registry and to decrypt them.
    .DESCRIPTION
        The script uses a predefined set of registry locations and properties.
        This whole script is mainly based on the description and scripts provided
        on https://whynotsecurity.com/blog/teamviewer/. I just thought a powershell
        version for this windows specific task would be nice to have.
    .EXAMPLE
        Just run "Get-TeamViewPasswords"
        


