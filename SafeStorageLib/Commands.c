#include "Commands.h"

// Global variables
static char g_AppDirectory[MAX_PATH] = { 0 };
static char g_CurrentLoggedInUser[11] = { 0 };
static BOOL g_IsUserLoggedIn = FALSE;
static CRITICAL_SECTION g_CriticalSection;

// Helper function prototypes
static NTSTATUS ValidateUsername(const char* Username, uint16_t UsernameLength);
static NTSTATUS ValidatePassword(const char* Password, uint16_t PasswordLength);
static NTSTATUS HashPassword(const char* Password, uint16_t PasswordLength, char* HashBuffer, size_t HashBufferSize);
static NTSTATUS CheckUserExists(const char* Username, uint16_t UsernameLength, BOOL* Exists);
static NTSTATUS SaveUserToFile(const char* Username, uint16_t UsernameLength, const char* PasswordHash);
static NTSTATUS CreateUserDirectory(const char* Username, uint16_t UsernameLength);


NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    DWORD length = 0;
    
    // Get current directory (%AppDir%)
    length = GetCurrentDirectoryA(MAX_PATH, g_AppDirectory);
    if (length == 0 || length >= MAX_PATH)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Initialize critical section
    InitializeCriticalSection(&g_CriticalSection);
    
    return STATUS_SUCCESS;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    // Clean up critical section
    DeleteCriticalSection(&g_CriticalSection);
    
    // Clear sensitive data
    SecureZeroMemory(g_CurrentLoggedInUser, sizeof(g_CurrentLoggedInUser));
    g_IsUserLoggedIn = FALSE;
    
    return;
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOL userExists = FALSE;
    char passwordHash[65] = { 0 };

    // Check if a user is already logged in
    EnterCriticalSection(&g_CriticalSection);
    if (g_IsUserLoggedIn)
    {
        LeaveCriticalSection(&g_CriticalSection);
        printf("Error: A user is already logged in. Please logout first.\r\n");
        return STATUS_INVALID_DEVICE_STATE;
    }
    LeaveCriticalSection(&g_CriticalSection);
    
    // Validate username
    status = ValidateUsername(Username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Invalid username. Username must be 5-10 characters and contain only English letters (a-zA-Z).\r\n");
        return status;
    }
    
    // Validate password
    status = ValidatePassword(Password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Invalid password. Password must be at least 5 characters, contain 1 digit, 1 lowercase, 1 uppercase, and 1 special character (!@#$%%^&).\r\n");
        return status;
    }
    
    // Check if user already exists
    status = CheckUserExists(Username, UsernameLength, &userExists);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Failed to check if user exists.\r\n");
        return status;
    }
    
    if (userExists)
    {
        printf("Error: This user already exists.\r\n");
        return STATUS_USER_EXISTS;
    }
    
    // Hash the password
    status = HashPassword(Password, PasswordLength, passwordHash, sizeof(passwordHash));
    if (!NT_SUCCESS(status))
    {
        printf("Error: Failed to hash password.\r\n");
        SecureZeroMemory(passwordHash, sizeof(passwordHash));
        return status;
    }
    
    // Create user directory
    status = CreateUserDirectory(Username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Failed to create user directory.\r\n");
        SecureZeroMemory(passwordHash, sizeof(passwordHash));
        return status;
    }
    
    // Save user to file
    status = SaveUserToFile(Username, UsernameLength, passwordHash);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Failed to save user to file.\r\n");
        SecureZeroMemory(passwordHash, sizeof(passwordHash));
        return status;
    }

    SecureZeroMemory(passwordHash, sizeof(passwordHash));

    printf("User registered successfully.\r\n");
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePath);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePath);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}

///////////////////////////////////////
// Helper Functions Implementation
///////////////////////////////////////

static NTSTATUS
ValidateUsername(
    const char* Username,
    uint16_t UsernameLength
)
{
    if (Username == NULL || UsernameLength < 5 || UsernameLength > 10)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    for (uint16_t i = 0; i < UsernameLength; i++)
    {
        if (!((Username[i] >= 'a' && Username[i] <= 'z') || 
              (Username[i] >= 'A' && Username[i] <= 'Z')))
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS
ValidatePassword(
    const char* Password,
    uint16_t PasswordLength
)
{
    BOOL hasDigit = FALSE;
    BOOL hasLowercase = FALSE;
    BOOL hasUppercase = FALSE;
    BOOL hasSpecial = FALSE;
    
    if (Password == NULL || PasswordLength < 5)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    for (uint16_t i = 0; i < PasswordLength; i++)
    {
        if (Password[i] >= '0' && Password[i] <= '9')
        {
            hasDigit = TRUE;
        }
        else if (Password[i] >= 'a' && Password[i] <= 'z')
        {
            hasLowercase = TRUE;
        }
        else if (Password[i] >= 'A' && Password[i] <= 'Z')
        {
            hasUppercase = TRUE;
        }
        else if (Password[i] == '!' || Password[i] == '@' || Password[i] == '#' || 
                 Password[i] == '$' || Password[i] == '%' || Password[i] == '^' || 
                 Password[i] == '&')
        {
            hasSpecial = TRUE;
        }
    }
    
    if (!hasDigit || !hasLowercase || !hasUppercase || !hasSpecial)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS
HashPassword(
    const char* Password,
    uint16_t PasswordLength,
    char* HashBuffer,
    size_t HashBufferSize
)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BYTE hash[32]; // SHA256 produces 32 bytes
    DWORD hashLength = 0;
    DWORD cbData = 0;
    
    if (Password == NULL || HashBuffer == NULL || HashBufferSize < 65)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    // Get hash object length
    status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return status;
    }
    
    // Create hash object
    status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return status;
    }
    
    // Hash the password
    status = BCryptHashData(hHash, (PBYTE)Password, PasswordLength, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return status;
    }
    
    // Finish the hash
    status = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return status;
    }
    
    // Convert hash to hex string
    for (DWORD i = 0; i < sizeof(hash); i++)
    {
        sprintf_s(HashBuffer + (i * 2), HashBufferSize - (i * 2), "%02x", hash[i]);
    }
    
    // Clean up
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    
    return STATUS_SUCCESS;
}

static NTSTATUS
CheckUserExists(
    const char* Username,
    uint16_t UsernameLength,
    BOOL* Exists
)
{
    FILE* file = NULL;
    char usersFilePath[MAX_PATH] = { 0 };
    char line[MAX_PATH] = { 0 };
    char storedUsername[11] = { 0 };
    HRESULT hr = S_OK;
    
    if (Username == NULL || Exists == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    *Exists = FALSE;
    
    // Build path to users.txt
    hr = StringCchPrintfA(usersFilePath, MAX_PATH, "%s\\users.txt", g_AppDirectory);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Open users.txt file
    errno_t err = fopen_s(&file, usersFilePath, "r");
    if (err != 0 || file == NULL)
    {
        return STATUS_SUCCESS;
    }
    
	// Search for username in file
    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* colon = strchr(line, ':');
        if (colon != NULL)
        {
            size_t usernameLen = colon - line;
            if (usernameLen == UsernameLength && usernameLen <= 10)
            {
                memcpy(storedUsername, line, usernameLen);
                storedUsername[usernameLen] = '\0';
                
                if (memcmp(storedUsername, Username, UsernameLength) == 0)
                {
                    *Exists = TRUE;
                    fclose(file);
                    return STATUS_SUCCESS;
                }
            }
        }
    }
    
    fclose(file);
    return STATUS_SUCCESS;
}

static NTSTATUS
SaveUserToFile(
    const char* Username,
    uint16_t UsernameLength,
    const char* PasswordHash
)
{
    FILE* file = NULL;
    char usersFilePath[MAX_PATH] = { 0 };
    HRESULT hr = S_OK;
    
    if (Username == NULL || PasswordHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Build path to users.txt
    hr = StringCchPrintfA(usersFilePath, MAX_PATH, "%s\\users.txt", g_AppDirectory);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Open file in append mode
    errno_t err = fopen_s(&file, usersFilePath, "a");
    if (err != 0 || file == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Write username and password hash (format: username:passwordhash)
    fprintf(file, "%.*s:%s\n", UsernameLength, Username, PasswordHash);
    
    fclose(file);
    return STATUS_SUCCESS;
}

static NTSTATUS
CreateUserDirectory(
    const char* Username,
    uint16_t UsernameLength
)
{
    char usersDirectory[MAX_PATH] = { 0 };
    char userDirectory[MAX_PATH] = { 0 };
    HRESULT hr = S_OK;
    
    if (Username == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Create users directory if it doesn't exist
    hr = StringCchPrintfA(usersDirectory, MAX_PATH, "%s\\users", g_AppDirectory);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    CreateDirectoryA(usersDirectory, NULL);
    
    // Create user-specific directory
    hr = StringCchPrintfA(userDirectory, MAX_PATH, "%s\\users\\%.*s", g_AppDirectory, UsernameLength, Username);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (!CreateDirectoryA(userDirectory, NULL))
    {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }
    
    return STATUS_SUCCESS;
}
