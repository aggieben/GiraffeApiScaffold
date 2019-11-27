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

    let handleGetHello =
        fun (next : HttpFunc) (ctx : HttpContext) ->
            task {
                let response = {
                    Text = "Hello world, from Giraffe!"
                }
                return! json response next ctx
            }