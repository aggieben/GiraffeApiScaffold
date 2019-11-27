namespace GiraffeApiScaffold
open System.Threading.Tasks
open FSharp.Control.Tasks.V2


module TaskResult =
    let map (f:'a->'b) (tr:Task<Result<'a,'e>>) = task {
        let! r = tr
        return Result.map f r
    }

    let mapErr (f:'e->'f) (tr:Task<Result<'a,'e>>) = task {
        let! r = tr
        return Result.mapError f r
    }
    
    let mapResultBindTaskResult (f:'a -> Task<Result<'b,'e>>) (r:Result<'a,'e>) = task {
        match r with
        | Ok ok -> return! f ok
        | Error err -> return Error err
    }

    let mapTaskResultBindResult (f:'a->Result<'b,'e>) (tr:Task<Result<'a,'e>>) = task {
        match! tr with 
        | Ok ok -> return f ok
        | Error err -> return Error err
    }

    let mapTaskResultBindTask (f:'a->Task<'b>) (tr:Task<Result<'a,'e>>) = task {
        match! tr with
        | Ok a -> 
            let! b = f a
            return Ok b
        | Error err -> 
            return Error err
    }

    let mapTaskBindTaskResult (f:'a->Task<Result<'b,'e>>) (t:Task<'a>) = task {
        let! a = t
        return! f a
    }

    let bind (f:'a->Task<Result<'b,'e>>) (a:'a) = f a
    let compose (f:'a->Task<Result<'b,'e>>) (tr:Task<Result<'a,'e>>) = task {
        match! tr with
        | Ok a -> return! f a
        | Error e -> return Error e
    }


    let inline (<*>) tr f = map f tr
    // let inline (<*!>) tr f = mapErr f tr

    // // partial maps
    let inline (<*->) tr f = mapTaskResultBindResult f tr
    // let inline (<*+>) tr f = mapTaskResultBindTask f tr

    // // partial binds
    // let inline (<+>>-) t f = mapTaskBindTaskResult f t
    // let inline (<->>-) r f = mapResultBindTaskResult f r

    // let inline (>>=) a f = bind f a
    // let inline (>=>) tr f = compose f tr

module Result =
    let bindOk (binder:'a->Result<'b,'e>) =
        function | Ok ok -> binder ok | Error err -> Error err
    let bindErr (binder:'e->Result<'a,'f>) =
        function | Ok ok -> Ok ok | Error err -> binder err

    let inline (<*>) r f = Result.map f r
    let inline (<*!>) r f = Result.mapError f r
    let inline (>>*=) r f = bindOk f r
    let inline (>>!*=) r f = bindErr f r