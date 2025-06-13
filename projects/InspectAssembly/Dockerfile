# Use the official .NET SDK image as the base image for building
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

# Copy the solution file and project files
COPY ["InspectAssembly.sln", "./"]
COPY ["InspectAssembly/InspectAssembly.csproj", "InspectAssembly/"]

# Restore NuGet packages
RUN dotnet restore

# Copy the remaining source code
COPY . .

# Build the application
RUN dotnet build "InspectAssembly/InspectAssembly.csproj" -c Release -o /app/build

# Publish the application
RUN dotnet publish "InspectAssembly/InspectAssembly.csproj" -c Release -o /app/publish

# Create the runtime image
FROM mcr.microsoft.com/dotnet/runtime:6.0
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "InspectAssembly.dll"]