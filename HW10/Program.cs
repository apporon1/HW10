using System;
using Microsoft.Data.SqlClient;
using BCrypt.Net;

public class UserAuthModule
{
    private string connectionString = "your_secure_connection_string";

    public void RegisterUser(string username, string password)
    {
        string query = "INSERT INTO Users (Username, PasswordHash) VALUES (@Username, @PasswordHash)";
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

        try
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@PasswordHash", passwordHash);

                    connection.Open();
                    command.ExecuteNonQuery();
                }
            }
        }
        catch (Exception ex)
        {
            LogError(ex);
            throw new ApplicationException("Произошла ошибка при регистрации пользователя.");
        }
    }

    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT PasswordHash FROM Users WHERE Username = @Username";

        try
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    connection.Open();
                    var passwordHash = command.ExecuteScalar() as string;

                    if (passwordHash != null)
                    {
                        return BCrypt.Net.BCrypt.Verify(password, passwordHash);
                    }

                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            LogError(ex);
            throw new ApplicationException("Произошла ошибка при авторизации пользователя.");
        }
    }

    private void LogError(Exception ex)
    {
        // Реализуйте безопасное логирование
        Console.WriteLine($"Ошибка: {ex.Message}");
    }
}
