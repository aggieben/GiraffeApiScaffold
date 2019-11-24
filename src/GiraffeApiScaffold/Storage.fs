namespace GiraffeApiScaffold
open System.Threading.Tasks
open FSharp.Control.Tasks.V2

type IRepository =
    abstract GetClientSecret : string -> Task<string option>

type Client =
    { clientId: string
      clientSecret: string }

module Storage =
    let clientList = [
        { clientId = "abc123"; clientSecret = "alphanumeric" }
        { clientId = "partner1"; clientSecret = "040152e1-09eb-45eb-aa7a-07c5d3c9f6b2" }
    ]

type Repository() =
    interface IRepository with
        member __.GetClientSecret(clientId:string) = task {
            return 
                Storage.clientList
                |> List.tryFind (fun c -> c.clientId = clientId)
                |> Option.map (fun c -> c.clientId)
        }
