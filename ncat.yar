rule ncat {
   meta: 
      description = "Windows binary version of Ncat 5.59BETA"
      source = "https://nmap.org/ncat/ "	
      author = "user_Honest"
      date = "22-12-2022"
      tags = "ncat, nc"
      reference = "research"

   strings: 
      $a1 = {4D 5A}
      $b2 = "nmap-dev@insecure.org" fullword ascii
      $b3 = "Usage: ncat " fullword ascii

   condition:
      $a1 at 0 and 2 of ( $b* )

}
