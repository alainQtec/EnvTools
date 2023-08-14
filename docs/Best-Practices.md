# Best practices when using Environment variables

## **Security best practices**

Here are some tips to handle environment variables on different platforms without facing security issues:

- **Do not share your environment variables**: Environment variables can contain sensitive information such as passwords and API keys. It is important to keep them private and not share them with others.

- **Do not keep the variables inside your code**: Hardcoding environment variables inside your code can make it difficult to manage them. Instead, you can use a `.env` file to store your environment variables.

- **Use a secure vault for encryption and decryption of your secret information**: You can use a secure vault such as [HashiCorp Vault](https://www.vaultproject.io/) or [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) to store your secrets.

- **Do not commit your environment variables to version controls like git**: Committing environment variables to version control systems like Git can expose them to others. Instead, you can use a `.gitignore` file to exclude them from version control.

## **Compatibility best practices**

Here are some tips to handle environment variables on different platforms without facing compatibility issues:

- **Use cross-platform scripting**: Cross-platform scripting can help you write scripts that work on different platforms. You can use tools like [Azure Pipelines](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/cross-platform-scripting?view=azure-devops) to write cross-platform scripts.

- **Use a `.env` file**: You can use a `.env` file to store your environment variables. This file can be read by different platforms.

- **Use your deployment platform’s variable storage**: Most deployment environments such as Heroku, AWS, Netlify, etc., provide a space for users to upload secrets which are later injected into the runtime of your application.
