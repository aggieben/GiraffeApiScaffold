namespace GiraffeApiScaffold
open System
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Http
open Microsoft.Net.Http.Headers
open FSharp.Control.Tasks.V2

module SignatureHelpers =
    let getSignature = 
        (fun (h:IHeaderDictionary) -> h.GetCommaSeparatedValues(HeaderNames.Authorization))
        >> Seq.tryFind (fun auth -> auth.StartsWith("Signature"))
        >> Option.map (fun auth -> auth.Split(" ").[1])

type SignatureAuthenticationOptions() =
    inherit AuthenticationSchemeOptions()
    member val Realm = String.Empty with get,set

type SignatureAuthenticationHandler(options, loggerFactory, encoder, clock) = 
    inherit AuthenticationHandler<SignatureAuthenticationOptions>(options, loggerFactory, encoder, clock)
        override this.HandleAuthenticateAsync() = task {
            let r = this.Request
            match SignatureHelpers.getSignature this with
            | None -> return ()
            | Some -> return ()
        }
