module GiraffeApiScaffold.App

open System
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Cors.Infrastructure
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Microsoft.Extensions.DependencyInjection
open Giraffe
open GiraffeApiScaffold.HttpHandlers

// ---------------------------------
// Web app
// ---------------------------------

let webApp =
    choose [
        subRoute "/api"
            (choose [
                GET >=> choose [
                    route "/hello" >=> 
                        requiresAuthentication unauthorizedHandler >=>
                            handleGetHello
                ]
            ])
        setStatusCode 404 >=> text "Not Found" ]

// ---------------------------------
// Error handler
// ---------------------------------

let errorHandler (ex : Exception) (logger : ILogger) =
    logger.LogError(ex, "An unhandled exception has occurred while executing the request.")
    clearResponse >=> setStatusCode 500 >=> text ex.Message

// ---------------------------------
// Config and Main
// ---------------------------------

let configureApp (app : IApplicationBuilder) =
    let env = app.ApplicationServices.GetService<IWebHostEnvironment>()
 
    (match env.EnvironmentName = Environments.Development with
    | true  -> app.UseDeveloperExceptionPage()
    | false -> app.UseGiraffeErrorHandler errorHandler)
        .UseHttpsRedirection()
        .UseAuthentication()
        .UseGiraffe(webApp)

let configureServices (services : IServiceCollection) =
    services
        .AddGiraffe()
        .AddDistributedMemoryCache()
        .AddScoped<IRepository,Repository>()
    |> ignore

    services.AddAuthentication("Signature")
        .AddScheme<SignatureAuthenticationOptions, SignatureAuthenticationHandler>("Signature",
            (fun opts -> 
                opts.Realm <- "GiraffeApiScaffold"))
    |> ignore

let configureLogging (builder : ILoggingBuilder) =
    builder.AddFilter(fun l -> true)
       .AddConsole()
       .AddDebug() |> ignore

[<EntryPoint>]
let main _ =
    WebHostBuilder()
        .UseKestrel()
        .UseIISIntegration()
        .ConfigureLogging(configureLogging)
        .Configure(Action<IApplicationBuilder> configureApp)
        .ConfigureServices(configureServices)
        .Build()
        .Run()
    0