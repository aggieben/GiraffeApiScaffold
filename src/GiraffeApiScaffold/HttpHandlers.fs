namespace GiraffeApiScaffold

open System
open Microsoft.Extensions.Caching.Distributed
open Microsoft.AspNetCore.Authentication

module HttpHandlers =

    open Microsoft.AspNetCore.Http
    open FSharp.Control.Tasks.V2.ContextInsensitive
    open Giraffe
    open GiraffeApiScaffold.Models

    let unauthorizedHandler (next:HttpFunc) (ctx:HttpContext) = task {
        let schemeProvider = ctx.GetService<IAuthenticationSchemeProvider>()
        let! schemes = schemeProvider.GetAllSchemesAsync()
        let schemesString = String.Join(",", schemes |> Seq.map (fun s -> s.Name))

        return! 
            (next,ctx) 
            ||> (RequestErrors.unauthorized schemesString "GiraffeApiScaffold" 
                    (text String.Empty))
    }

    let handleGetNonce (next:HttpFunc) (ctx:HttpContext) = task {
        match ctx.TryGetQueryStringValue("clientId") with
        | None -> return! (next,ctx) ||> (RequestErrors.badRequest (text "required parameter clientId not provided."))
        | Some clientId ->
            let repo = ctx.GetService<IRepository>()
            match! repo.GetClientSecret(clientId) with
            | None -> return! (next,ctx) ||> (RequestErrors.badRequest (text "invalid client"))
            | Some _ ->
                let cache = ctx.GetService<IDistributedCache>()
                let nonce = Guid.NewGuid().ToByteArray()
                let expiry = DateTimeOffset.UtcNow.AddMinutes(5.0)
                do! cache.SetAsync(
                        sprintf "%s:nonce" clientId, 
                        nonce, 
                        DistributedCacheEntryOptions(AbsoluteExpiration = Nullable(expiry)))
                let encodedNonce = Convert.ToBase64String nonce
                return! (next,ctx) ||> (json encodedNonce)
    }

    let handleGetHello =
        fun (next : HttpFunc) (ctx : HttpContext) ->
            task {
                let response = {
                    Text = "Hello world, from Giraffe!"
                }
                return! json response next ctx
            }