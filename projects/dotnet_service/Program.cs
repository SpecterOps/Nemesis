using Dapr.Client;
using ILSpyDecompilerService;
using ILSpyDecompilerService.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc;
using System;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers().AddDapr();

builder.Services.AddControllers().AddNewtonsoftJson();

// Add our custom services
builder.Services.AddSingleton<MinioService>();
builder.Services.AddSingleton<DecompilerEngine>();
builder.Services.AddSingleton<AssemblyAnalysisService>();

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseRouting();
app.UseCloudEvents();
app.MapControllers();
app.MapSubscribeHandler();

// Add health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

app.Run();