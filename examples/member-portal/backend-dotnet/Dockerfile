FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution projects
COPY remediate/ remediate/
COPY examples/member-portal/backend-dotnet/ examples/member-portal/backend-dotnet/

RUN dotnet publish examples/member-portal/backend-dotnet/MemberPortal.Backend.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
RUN mkdir -p /app/data
EXPOSE 5001
ENTRYPOINT ["dotnet", "MemberPortal.Backend.dll"]
