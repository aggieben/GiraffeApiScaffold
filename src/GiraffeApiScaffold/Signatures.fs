namespace GiraffeApiScaffold
open System
open System.Collections.Generic
open System.Security.Claims
open System.Security.Cryptography
open System.Text
open System.Text.RegularExpressions
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Caching.Distributed
open Microsoft.Extensions.Logging
open Microsoft.Net.Http.Headers
open FSharp.Control.Tasks.V2
open FSharp.Data.UnitSystems.SI.UnitSymbols
open Giraffe.ComputationExpressions


open Result
open TaskResult

type SignatureAlgorithm =
    | HmacSha256
    with
        static member TryParse (raw:string) =
            match raw with
            | "hmac-sha256" -> Some HmacSha256 
            | _ -> None

type SignatureAuthenticationOptions() =
    inherit AuthenticationSchemeOptions()
    member val Realm = String.Empty with get,set
    member val SupportedAlgorithms = [| HmacSha256 |] with get,set
    member val MaxClockSkew = 600<s> with get,set

type SignatureParsingError =
    | MissingHeaderValue
    | InvalidParameters of string seq option

type SignatureValidationError =
    | RequiredParametersMissing of string seq
    | InvalidAlgorithm
    | InvalidCreatedTimestamp of string
    | InvalidExpiresTimestamp of string
    | InvalidHeaders

(*
    example:
    Authorization: Signature keyId="rsa-key-1",algorithm="hs2019",
     headers="(request-target) (created) host digest content-length",
     signature="Base64(RSA-SHA512(signing string))"
*)
type UnvalidatedSignatureEnvelope =
    { keyId: string option
      signature: string option
      algorithm: string option
      created: string option
      expires: string option
      headers: string option }
   with
        static member TryParse (raw:string) =
            let tryGetValue (map:Map<_,_>) key =
                match map.TryGetValue(key) with
                | (true, v) -> Some v
                | (false, v) -> None

            try
                match Regex.Matches(@"[^=,""]", raw) with
                | tokenlist when tokenlist.Count % 2 <> 0 -> 
                    InvalidParameters None |> Error
                | tokenlist ->
                    Seq.chunkBySize 2 tokenlist 
                    |> Seq.map (fun chunk -> (chunk.[0].Value, chunk.[1].Value))
                    |> Map.ofSeq
                    |> Ok
            with
            | e -> InvalidParameters None |> Error
            |> Result.bind
                (fun map -> 
                    { keyId =tryGetValue map "keyId"
                      signature = tryGetValue map "signature"
                      algorithm = tryGetValue map "algorithm"
                      created = tryGetValue map "created"
                      expires = tryGetValue map "expires"
                      headers = tryGetValue map "headers" } |> Ok)

type SignatureEnvelope =
    { keyId: string
      signature: byte[]
      algorithm: SignatureAlgorithm option
      created: DateTimeOffset option
      expires: DateTimeOffset option
      headers: string[] option }


                // (fun map ->
                //     let missingRequired = 
                //         [ "keyId"; "signature" ]
                //         |> List.filter (map.ContainsKey >> not)

                //     if missingRequired.Length <> 0 then 
                //         RequiredParametersMissing missingRequired |> Error
                //     else
                //         let keyId = map.["keyId"]
                //         let signature = map.["signature"] |> Convert.FromBase64String
                //         let algorithm = SignatureAlgorithm.TryParse map.["algorithm"]
                //         let created = parseDateTimeOffset map "created"
                //         let expires = parseDateTimeOffset map "expires"
                //         let headers = 
                //             if map.ContainsKey "headers" 
                //             then map.["headers"].Split(' ', StringSplitOptions.RemoveEmptyEntries)
                //                  |> Some
                //             else None

                //         { keyId = keyId 
                //           signature = signature
                //           algorithm = algorithm
                //           created = created
                //           expires = expires
                //           headers = headers }
                //         |> Ok )

module private SignatureHelpers =

    type private SignatureEnvelopeValidationState =
        { unvalidatedEnvelope : UnvalidatedSignatureEnvelope
          validatedEnvelope : SignatureEnvelope }

    type private SignatureValidationState =
        { envelope: SignatureEnvelope option
          signature: ReadOnlyMemory<byte> option
          clientSecret : byte[] option 
          checkSignature : byte[] option }
        with 
            static member Default =
                { envelope = None
                  signature = None
                  clientSecret = None
                  checkSignature = None }

    type SignatureValidationError =
        | NonceExpired
        | InvalidClient
        | InvalidSignature

    // let ensureArrayLength array length =
    //     if Array.length array = length then Ok array else Error InvalidSignature

    // let decodeSignature (encSig:string) =
    //     let bytes : byte[] = Array.zeroCreate encSig.Length
    //     let byteCountRef = ref 0
    //     if Convert.TryFromBase64String(encSig, bytes.AsSpan(), byteCountRef) then
    //         ReadOnlyMemory(bytes).Slice(0, !byteCountRef) |> Ok
    //     else
    //         Error InvalidSignature
    let getSignatureHeaderValue = 
        (fun (h:IHeaderDictionary) -> h.GetCommaSeparatedValues(HeaderNames.Authorization))
        >> Seq.tryFind (fun auth -> auth.StartsWith("Signature"))
        >> Option.map (fun auth -> auth.IndexOf(' ') |> auth.Substring)

    let getUnvalidatedSignatureEnvelope (request:HttpRequest) =
        match getSignatureHeaderValue request.Headers with
        | None -> Error MissingHeaderValue
        | Some headerValue -> UnvalidatedSignatureEnvelope.TryParse headerValue

    let validateRequiredParams (unvalidatedEnvelope:UnvalidatedSignatureEnvelope) =
        let missingRequiredFields = 
            match unvalidatedEnvelope.keyId with 
            | None -> ["keyId"]
            | Some s -> if String.IsNullOrEmpty(s) then ["keyId"] else []
            |> (fun mrf -> 
                   match unvalidatedEnvelope.signature with
                   | None -> "signature"::mrf
                   | Some s -> if String.IsNullOrEmpty(s) then "signature"::mrf else mrf)
        
        if not missingRequiredFields.IsEmpty
        then RequiredParametersMissing missingRequiredFields |> Error
        else
            { unvalidatedEnvelope = unvalidatedEnvelope
              validatedEnvelope = 
                { keyId = unvalidatedEnvelope.keyId.Value
                  signature = Convert.FromBase64String(unvalidatedEnvelope.signature.Value)
                  algorithm = None
                  created = None
                  expires = None
                  headers = None }} |> Ok

    let validateAlgorithm (options:SignatureAuthenticationOptions) (state:SignatureEnvelopeValidationState) =
        match state.unvalidatedEnvelope.algorithm with
        | None -> Ok state
        | Some algorithmName -> 
            match SignatureAlgorithm.TryParse algorithmName with
            | None -> InvalidAlgorithm |> Error
            | Some algo -> 
                if Array.contains algo options.SupportedAlgorithms
                then Ok {state with validatedEnvelope = { state.validatedEnvelope with algorithm = Some algo }}
                else InvalidAlgorithm |> Error

    let validateCreated (options:SignatureAuthenticationOptions) (state:SignatureEnvelopeValidationState) =
        // §2.1.4: must be unix timestamp.  future timestamp must fail.  second precision.
        match state.unvalidatedEnvelope.created with
        | None -> Ok state
        | Some tsString -> 
            let tsValue = ref 0L
            if Int64.TryParse(tsString, tsValue) |> not
            then InvalidCreatedTimestamp "'created' field not a valid unix timestamp" |> Error
            else
                try
                    match DateTimeOffset.FromUnixTimeSeconds(!tsValue) with
                    | timestamp when timestamp > (DateTimeOffset.UtcNow.AddSeconds(float options.MaxClockSkew)) -> 
                        InvalidCreatedTimestamp "'created' timestamp in the future" |> Error
                    | timestamp -> Ok { state with validatedEnvelope = { state.validatedEnvelope with created = Some timestamp}}
                with
                | e -> InvalidCreatedTimestamp e.Message |> Error

    let validateExpires (options:SignatureAuthenticationOptions) (state:SignatureEnvelopeValidationState) =
        // §2.1.5: must be unix integer, subsecond allowed. past timestamp fails
        match state.unvalidatedEnvelope.expires with
        | None -> Ok state
        | Some tsString ->
            let tsValue = ref 0L
            if Int64.TryParse(tsString,tsValue) |> not
            then InvalidExpiresTimestamp "'expires' field not a valid unix timestamp" |> Error
            else
                try match DateTimeOffset.FromUnixTimeSeconds(!tsValue) with
                    | timestamp when timestamp < (DateTimeOffset.UtcNow.AddSeconds(float -options.MaxClockSkew)) ->
                        InvalidExpiresTimestamp "'expires' timestamp in the past" |> Error
                    | timestamp -> Ok { state with validatedEnvelope = { state.validatedEnvelope with expires = Some timestamp }}
                with
                | e -> InvalidExpiresTimestamp e.Message |> Error

    let validateHeaders (options:SignatureAuthenticationOptions) (state:SignatureEnvelopeValidationState) =
        // §2.1.6: if not specified, then default is "(created)".  empty is different that non-specified
        match state.unvalidatedEnvelope.headers with
        | None -> Ok state
        | Some hString ->
            if String.IsNullOrWhiteSpace(hString)
            then InvalidHeaders |> Error
            else { state with 
                    validatedEnvelope = 
                        { state.validatedEnvelope with 
                            headers = hString.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                      |> Option.ofObj } } 
                 |> Ok

    let validateSignatureEnvelope (options:SignatureAuthenticationOptions) (usigenv:UnvalidatedSignatureEnvelope) = 
        validateRequiredParams usigenv
        >>*= validateAlgorithm options
        >>*= validateCreated options
        >>*= validateExpires options
        >>*= validateHeaders options

    let ensureClientSecretAsync (repository:IRepository) state = task {
        let envelope = state.envelope.Value
        match! repository.GetClientSecret(envelope.keyId) with
        | None -> return InvalidClient |> Error
        | Some secret ->
            let key = Encoding.UTF8.GetBytes(secret)
            return { state with clientSecret = Some key } |> Ok
    }

    // let computeCheckSignature state = 
    //     use hmac = new HMACSHA256(state.clientSecret.Value)
    //     { state with 
    //         checkSignature = hmac.ComputeHash(state.nonce.Value) 
    //                          |> Some}

    // let compareSignatures state =
    //     let sigSpan = state.signature.Value.Span
    //     let checkSigSpan = ReadOnlySpan(state.checkSignature.Value)
    //     match checkSigSpan.SequenceCompareTo(sigSpan) with
    //     | 0 -> Ok state
    //     | _ -> Error InvalidSignature

    let validateSignature (repository:IRepository) (options:SignatureAuthenticationOptions) (sigenv:SignatureEnvelope) =
        ensureClientSecretAsync repository { SignatureValidationState.Default 
                                                with envelope = Some sigenv }
        
        // <*>     computeCheckSignature
        // <*->    compareSignatures
        // <*>     (fun state -> state.clientId.Value) // drop state

// https://datatracker.ietf.org/doc/draft-cavage-http-signatures/?include_text=1
(*
    Signature params:
        ** required **
        - keyId [*] : opaque string for lookup
        - signature [*] : base64-encoded, derived from a signing string 
            comprised of `algorithm` and `headers` and then signed using the key
            associated with `keyId`
        ** recommended **
        - algorithm : must match algorithm associated with keyId.  hmac-sha256 for our purposes.
        - created: unix timestamp denoting when the signature was created.  if 
            timestamp in the future the signature must not be processed.
            sub-seconds not allowed
        ** optional **
        - expires: when the signature ceases to be valid; a unix timestamp. if 
            timestamp is in the past, the signature must not be processed.  
            sub-seconds allowed (but I'm not going to support it)
        - headers: lowercased, quoted list of HTTP header fields used for the signature
            if not specified, the default is "created"
            list order is important, and must be specified in the order the field-value
            pairs are concatenated together in the signing string
            a zero-length string is not allowed here, because it would specify an
            empty signing string.

        if any params are duplicated, the signature must not be processed

        signing string is constructed:

*)

type SignatureAuthenticationHandler(options, loggerFactory, encoder, clock, cache:IDistributedCache, repository:IRepository) = 
    inherit AuthenticationHandler<SignatureAuthenticationOptions>(options, loggerFactory, encoder, clock)
        override this.HandleAuthenticateAsync() = 
            // this is necessary because the compiler machinery will place the expressions in the computational
            // expression below into a lambda, which takes them _out_ of the context of the class where the this
            // binding is accessible.  This binding is then captured as part of the closure for the CE
            let request = this.Request
            let logger = loggerFactory.CreateLogger<SignatureAuthenticationHandler>()
            task {
                match SignatureHelpers.getUnvalidatedSignatureEnvelope request with
                | Error e -> 
                    logger.LogError("Error getting signature envelope: {0}", sprintf "%A" e)
                    return AuthenticateResult.NoResult()
                | Ok unvalidatedEnvelope -> 
                    match SignatureHelpers.validateSignatureEnvelope options unvalidatedEnvelope with
                    | Error e ->
                        logger.LogError("Error validating signature: {0}", sprintf "%A" e)
                        return AuthenticateResult.NoResult()
                    | Ok envelope ->
                        let! validationResult = 
                            SignatureHelpers.validateSignature options envelope
                        match validationResult with
                        | Error err -> return AuthenticateResult.Fail (sprintf "%A" err)
                        | Ok clientId ->
                            let! principal = this.GetClaimsPrincipalForClient(clientId)
                            let ticket = AuthenticationTicket(principal, this.Scheme.Name)
                            return AuthenticateResult.Success(ticket)
            }

    member this.GetClaimsPrincipalForClient(clientId:string) =
        let scheme = this.Scheme
        task {
            return 
                ClaimsPrincipal(ClaimsIdentity([|
                    Claim(ClaimTypes.Name, clientId)
                |], scheme.Name)) }
