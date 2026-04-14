using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CivicTrackWebApp.Data;
using CivicTrackWebApp.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// 1. Core Services
builder.Services.AddRazorPages();

// 2. Database Configuration (SQL Server)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 3. Identity & Security Services
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

// 4. JWT Configuration
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.ASCII.GetBytes(jwtSettings["Key"] ?? "CivicTrack_Super_Secure_Secret_Key_2026_!!");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"] ?? "CivicTrackApi",
        ValidAudience = jwtSettings["Audience"] ?? "CivicTrackClients",
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

builder.Services.AddAuthorization();

// 5. Build App
var app = builder.Build();

// 6. Configure Pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Seeder logic for Categories & Users
using (var scope = app.Services.CreateScope())
{
    var devProvider = scope.ServiceProvider;
    var db = devProvider.GetRequiredService<ApplicationDbContext>();
    var hasher = devProvider.GetRequiredService<IPasswordHasher<User>>();
    
    if (db.Database.CanConnect())
    {
        // 1. Seed Categories (Specific Protocol List)
        if (!db.Categories.Any())
        {
            db.Categories.AddRange(
                new Category { Id = Guid.NewGuid(), Name = "Road", Description = "Street repairs, potholes, and drainage." },
                new Category { Id = Guid.NewGuid(), Name = "Water", Description = "Supply issues, leaks, and quality." },
                new Category { Id = Guid.NewGuid(), Name = "Electricity", Description = "Outages, dangerous wiring, and lighting." },
                new Category { Id = Guid.NewGuid(), Name = "Security", Description = "Public safety and neighborhood concerns." },
                new Category { Id = Guid.NewGuid(), Name = "Other", Description = "General community grievances." }
            );
        }

        // 2. Seed Admin & Officer (Professional Defaults)
        if (!db.Users.Any(u => u.Role == UserRole.Admin))
        {
            var admin = new User { 
                Id = Guid.NewGuid(), FullName = "System Administrator", Email = "admin@civictrack.rw", 
                Phone = "+250000000001", Role = UserRole.Admin, IsActive = true, CreatedAt = DateTime.UtcNow 
            };
            admin.PasswordHash = hasher.HashPassword(admin, "Admin@123");
            db.Users.Add(admin);
        }

        if (!db.Users.Any(u => u.Role == UserRole.Officer))
        {
            var officer = new User { 
                Id = Guid.NewGuid(), FullName = "Case Officer Operations", Email = "officer@civictrack.rw", 
                Phone = "+250000000002", Role = UserRole.Officer, IsActive = true, CreatedAt = DateTime.UtcNow 
            };
            officer.PasswordHash = hasher.HashPassword(officer, "Officer@123");
            db.Users.Add(officer);
        }

        db.SaveChanges();
    }
}

// app.UseHttpsRedirection(); // Disabled for local dev simplicity as requested
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// --- UNIFIED API ENDPOINTS ---

app.MapPost("/api/auth/login", async (LoginRequest request, ApplicationDbContext db, IPasswordHasher<User> hasher, IConfiguration config) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == request.Email || u.Phone == request.Email);
    if (user == null || hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
    {
        return Results.Unauthorized();
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role.ToString()),
            new Claim("FullName", user.FullName)
        }),
        Expires = DateTime.UtcNow.AddDays(7),
        Issuer = config["Jwt:Issuer"] ?? "CivicTrackApi",
        Audience = config["Jwt:Audience"] ?? "CivicTrackClients",
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new 
    { 
        token = tokenHandler.WriteToken(token),
        user = new { user.Id, user.FullName, user.Email, user.Role }
    });
});

app.MapPost("/api/auth/register", async (RegisterRequest request, ApplicationDbContext db, IPasswordHasher<User> hasher) =>
{
    if (await db.Users.AnyAsync(u => u.Email == request.Email))
        return Results.BadRequest("Email already registered.");

    var user = new User
    {
        Id = Guid.NewGuid(),
        FullName = request.FullName,
        Email = request.Email,
        Phone = request.Phone,
        Role = UserRole.Citizen,
        IsActive = true,
        CreatedAt = DateTime.UtcNow
    };
    user.PasswordHash = hasher.HashPassword(user, request.Password);

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Email });
});

app.MapGet("/api/categories", async (ApplicationDbContext db) => 
    Results.Ok(await db.Categories.Select(c => new { c.Id, c.Name }).ToListAsync()));

app.MapGet("/api/dashboard/stats", async (ClaimsPrincipal user, ApplicationDbContext db) =>
{
    var userId = Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    var roleStr = user.FindFirst(ClaimTypes.Role)!.Value;
    var role = Enum.Parse<UserRole>(roleStr);

    IQueryable<Complaint> query = db.Complaints;
    if (role == UserRole.Citizen) query = query.Where(c => c.CitizenId == userId);

    return Results.Ok(new {
        total = await query.CountAsync(),
        pending = await query.CountAsync(c => c.Status == ComplaintStatus.Pending),
        resolved = await query.CountAsync(c => c.Status == ComplaintStatus.Resolved || c.Status == ComplaintStatus.Closed),
        inProgress = await query.CountAsync(c => c.Status == ComplaintStatus.UnderReview || c.Status == ComplaintStatus.ActionTaken)
    });
}).RequireAuthorization();

app.MapGet("/api/complaints", async (ClaimsPrincipal user, ApplicationDbContext db) => 
{
    var userId = Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    var roleStr = user.FindFirst(ClaimTypes.Role)!.Value;
    var role = Enum.Parse<UserRole>(roleStr);

    var query = db.Complaints.Include(c => c.Category).AsQueryable();
    if (role == UserRole.Citizen) query = query.Where(c => c.CitizenId == userId);

    return Results.Ok(await query.OrderByDescending(c => c.SubmittedAt).ToListAsync());
}).RequireAuthorization();

app.MapPost("/api/complaints", async (ClaimsPrincipal user, ComplaintRequest request, ApplicationDbContext db) =>
{
    var userId = Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    
    var category = await db.Categories.FindAsync(request.CategoryId);
    if (category == null) return Results.BadRequest("Invalid category.");

    // Auto-Priority Logic
    var priority = ComplaintPriority.Medium;
    if (category.Name == "Security" || category.Name == "Electricity") 
    {
        priority = ComplaintPriority.Urgent;
    }

    var complaint = new Complaint
    {
        Id = Guid.NewGuid(),
        TrackingCode = "CIV-" + new Random().Next(100000, 999999),
        Title = request.Title,
        Description = request.Description,
        Location = request.Location,
        CategoryId = request.CategoryId,
        CitizenId = userId,
        Priority = priority,
        Status = ComplaintStatus.Pending,
        SubmittedAt = DateTime.UtcNow
    };

    db.Complaints.Add(complaint);
    await db.SaveChangesAsync();
    return Results.Ok(complaint);
}).RequireAuthorization();

app.MapPatch("/api/complaints/{id:guid}/status", async (Guid id, ComplaintStatus status, ApplicationDbContext db) =>
{
    var complaint = await db.Complaints.FindAsync(id);
    if (complaint == null) return Results.NotFound();

    complaint.Status = status;
    if (status == ComplaintStatus.Resolved) complaint.ResolvedAt = DateTime.UtcNow;
    await db.SaveChangesAsync();
    return Results.Ok(new { status = "updated", newStatus = status.ToString() });
}).RequireAuthorization();

// Razor Pages Map
app.MapRazorPages();

app.Run();

public record ComplaintRequest(string Title, string Description, string Location, Guid CategoryId);
