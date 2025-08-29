
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build

WORKDIR /src

# Copy project file and restore dependencies (fix the path)
COPY ./projects/dotnet_service/ILSpyDecompilerService.csproj ./projects/dotnet_service/
RUN dotnet restore ./projects/dotnet_service/ILSpyDecompilerService.csproj

# Copy source code and build
COPY ./projects/dotnet_service/ ./projects/dotnet_service/
WORKDIR /src/projects/dotnet_service
RUN dotnet build ILSpyDecompilerService.csproj -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish ILSpyDecompilerService.csproj -c Release -o /app/publish

# Development stage (for hot reload and debugging)
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS dev
WORKDIR /app
COPY ./projects/dotnet_service/ .
RUN dotnet restore
EXPOSE 5000
ENTRYPOINT ["dotnet", "run", "--urls", "http://0.0.0.0:5000"]

# Production runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS prod
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=publish /app/publish .

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000
ENTRYPOINT ["dotnet", "ILSpyDecompilerService.dll", "--urls", "http://0.0.0.0:5000"]