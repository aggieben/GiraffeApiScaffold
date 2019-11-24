namespace GiraffeApiScaffold
open System
open System.Security.Claims
open System.Security.Cryptography
open System.Text
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Caching.Distributed
open Microsoft.Net.Http.Headers
open FSharp.Control.Tasks.V2
open System.Collections.Generic

open Result
open TaskResult

module SignatureHelpers =
    let getSignature = 
        (fun (h:IHeaderDictionary) -> h.GetCommaSeparatedValues(HeaderNames.Authorization))
        >> Seq.tryFind (fun auth -> auth.StartsWith("Signature"))
        >> Option.map (fun auth -> auth.Split(" ").[1])

    type SignatureValidationState =
        { clientId : string option
          signature: ReadOnlyMemory<byte> option
          nonce : byte[] option
          clientSecret : byte[] option 
          checkSignature : byte[] option }
        with 
            static member Default =
                { clientId = None
                  signature = None
                  nonce = None
                  clientSecret = None
                  checkSignature = None }

    type SignatureValidationError =
        | NonceExpired
        | InvalidClient
        | InvalidSignature

    let ensureArrayLength array length =
        if Array.length array = length then Ok array else Error InvalidSignature

    let decodeSignature (encSig:string) =
        let bytes : byte[] = Array.zeroCreate encSig.Length
        let byteCountRef = ref 0
        if Convert.TryFromBase64String(encSig, bytes.AsSpan(), byteCountRef) then
            ReadOnlyMemory(bytes).Slice(0, !byteCountRef) |> Ok
        else
            Error InvalidSignature

    let parseAuthorizationHeader auth =
        Convert.FromBase64String auth
        |> Encoding.UTF8.GetString
        |> (fun s -> s.Split(':'))
        |> (fun arr -> ensureArrayLength arr 2)
        |> Result.bind
            (fun arr -> 
                decodeSignature arr.[1]
                |> Result.map (fun s -> { SignatureValidationState.Default with
                                            clientId = Some arr.[0]
                                            signature = Some s }))

    let ensureNonceAsync (cache:IDistributedCache) state = task {
        let! nonce = cache.GetAsync(sprintf "%s:nonce" state.clientId.Value)
        return 
            match isNull nonce with
            | true -> Error NonceExpired
            | false -> Ok { state with nonce = Some nonce }
    }

    let ensureClientSecretAsync (repository:IRepository) state = task {
        match! repository.GetClientSecret(state.clientId.Value) with
        | None -> return InvalidClient |> Error
        | Some secret ->
            let key = Encoding.UTF8.GetBytes(secret)
            return { state with clientSecret = Some key } |> Ok
    }

    let computeCheckSignature state = 
        use hmac = new HMACSHA256(state.clientSecret.Value)
        { state with 
            checkSignature = hmac.ComputeHash(state.nonce.Value) 
                             |> Some}

    let compareSignatures state =
        let sigSpan = state.signature.Value.Span
        let checkSigSpan = ReadOnlySpan(state.checkSignature.Value)
        match checkSigSpan.SequenceCompareTo(sigSpan) with
        | 0 -> Ok state
        | _ -> Error InvalidSignature

    let validateSignature (repository:IRepository) (cache:IDistributedCache) (clock:ISystemClock) authorization =
        parseAuthorizationHeader authorization
        <->>-   ensureNonceAsync cache
        >=>     ensureClientSecretAsync repository
        <*>     computeCheckSignature
        <*->    compareSignatures
        <*>     ignore // drop state

type SignatureAuthenticationOptions() =
    inherit AuthenticationSchemeOptions()
    member val Realm = String.Empty with get,set

type SignatureAuthenticationHandler(options, loggerFactory, encoder, clock, cache:IDistributedCache, repository:IRepository) = 
    inherit AuthenticationHandler<SignatureAuthenticationOptions>(options, loggerFactory, encoder, clock)
        override this.HandleAuthenticateAsync() = 
            let request = this.Request
            task {
                match SignatureHelpers.getSignature request.Headers with
                | None -> return AuthenticateResult.NoResult()
                | Some _ -> 
                    // TODO: validate the signature here
                    let! principal = this.GetClaimsPrincipalForClient(String.Empty)
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
