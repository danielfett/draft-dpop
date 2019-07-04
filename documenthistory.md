# Document History

   [[ To be removed from the final specification ]]

   -02
   
   * added normalization rules for URIs
   * removed distinction between proof and binding ("DPoP X JWT" -> "DPoP token")
   * "jwk" header again used instead of "cnf" claim in DPoP tokens
   * renamed "Bearer-DPoP" token type to "DPoP"
   * removed ability for key rotation
   * added security considerations on request integrity
   * explicit advice on extending DPoP tokens to sign other parts of the HTTP messages
   * only use the jkt#S256 in ATs
   * iat instead of exp in DPoP tokens
   * updated guidance on token_type evaluation


   -01
   
   * fixed inconsistencies
   * moved binding and proof messages to headers instead of parameters
   * extracted and unified definition of DPoP JWTs
   * improved description


   -00 

   *  first draft
   

   
