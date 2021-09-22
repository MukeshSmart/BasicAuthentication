using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace BasicAuthentication.Authentication
{
    public class BasicAuthenticationAttribute: AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
           if(actionContext.Request.Headers.Authorization!=null)
            {
                var authToken = actionContext.Request.Headers.Authorization.Parameter;

                var decodeToken = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(authToken));

                var userNamePassword = decodeToken.Split(':');

                if(IsAuthorizedUser(userNamePassword[0],userNamePassword[1]))
                {
                    Thread.CurrentPrincipal = new GenericPrincipal(
                        new GenericIdentity(userNamePassword[0]), null);
                }
                else
                {
                    actionContext.Response = actionContext.Request
                        .CreateResponse(HttpStatusCode.Unauthorized);
                }
            }
            else
            {
                actionContext.Response = actionContext.Request
                    .CreateResponse(HttpStatusCode.Unauthorized);
            }
        }

        public static bool IsAuthorizedUser(string Username, string Password)
        {
            // In this method we can handle our database logic here...  
            return Username == "mukesh" && Password == "demo";
        }
    }

   
}