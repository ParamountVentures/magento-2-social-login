# Magento 2 Social Login by Mageplaza

**Magento 2 Social Login extension** is designed for quick login to your Magento store without procesing complex register steps. Let say goodbye the complicated registration process and ignore a lot of unnecessarily required fields. *Magento 2 Social Login extension* is simply and powerful tool to integrate your Magento customer account to Facebook, Google Plus, Twitter, LinkedIn, and Instagram channel. Logging in via the social medias is the great idea to enhance your customer’s satisfaction.

### Highlight features for Social Login

- Quickly login step with five most common social channels
- Easy to change the personal information after registering
- The biggest preparation step for the loyalty of customers

[![Latest Stable Version](https://poser.pugx.org/mageplaza/magento-2-social-login/v/stable)](https://packagist.org/packages/mageplaza/magento-2-social-login)
[![Total Downloads](https://poser.pugx.org/mageplaza/magento-2-social-login/downloads)](https://packagist.org/packages/mageplaza/magento-2-social-login)

## 1. Documentation

- [Installation guide](https://www.mageplaza.com/install-magento-2-extension/)
- [User Guide](https://docs.mageplaza.com/social-login-m2/index.html)
- [Download from our Live site](https://www.mageplaza.com/magento-2-social-login-extension/)
- [Get Free Support](https://github.com/mageplaza/magento-2-social-login/issues)
- Get premium support from Mageplaza: [Purchase Support package](https://www.mageplaza.com/magento-2-extension-support-package/)
- [Contribute on Github](https://github.com/mageplaza/magento-2-social-login/)
- [Releases](https://github.com/mageplaza/magento-2-social-login/releases)
- [License](https://www.mageplaza.com/LICENSE.txt)


## 2. How to install

* Note that just now you need to use a branch of hybridauth to allow this to work.

## ✓ Install via composer (recommend)
Run the following command in Magento 2 root folder:

```
composer config repositories.repo-name vcs https://github.com/ParamountVentures/hybridauth 
composer require hybridauth/hybridauth:dev-b2c-beta 
composer config repositories.repo-name vcs https://github.com/ParamountVentures/magento-2-social-login 
composer require paramountventures/magento-2-social-login:dev-master
php bin/magento setup:upgrade
php bin/magento setup:static-content:deploy
```

### ✓ Install ready-to-paste package

- Download the latest version at [Mageplaza Social Login for Magento 2](https://www.mageplaza.com/magento-2-social-login-extension/)
-  [Installation guide](https://www.mageplaza.com/install-magento-2-extension/)



## 3. FAQs

#### Q: When I click on Login link, the popup does't work
A: You can read https://github.com/mageplaza/magento-2-social-login/issues/39

#### Q: I am using custom theme, it is compatible with our design?
A: We have developed Social Login based on Magento coding standard and best practice test on Magento Community and Magento Enterpise site. So it is compatible with themes and custom designs. Ask Magento community on http://magento.stackexchange.com/ or https://github.com/mageplaza/magento-2-social-login/issues/

#### Q: Can I install it by myself?
A: Yes, you absolutely can! You can install it like installing any extensions to website, follow our Installation Guide http://docs.mageplaza.com/kb/installation.html. User guide: https://docs.mageplaza.com/social-login-m2/index.html

#### Q: I got this message `Erro: invalid_scope`
A: Read this https://github.com/mageplaza/magento-2-social-login/issues/42

#### Q: I got error: `Mageplaza_Core has been already defined`
A: Read solution: https://github.com/mageplaza/module-core/issues/3

#### Q: My site is down
A: Please follow this guide: https://www.mageplaza.com/blog/magento-site-down.html



## 4. User guide


Customers are not patient enough to fill a lot of required information while those are available in social account as Facebook, LinkedIn, Instagram,.... [Magento 2 Social Login extension by Mageplaza](https://www.mageplaza.com/magento-2-social-login-extension/), your customers only need to click on the social button and all necessary information is completed automatically.That is the main reason why Magento Social Login extension is considered as the great solution for that convenience.

Login to Magento Admin and do as the following:

![social login](https://cdn.mageplaza.com/docs/social-settings.gif)

### General Configuration


#### Enable the module


Go to `Admin Panel > Social Login > Settings > General`

![enable social login](https://i.imgur.com/jNcIDpg.png)

Select `Yes` option in order to allow customers to sign in quickly via social channels they are using.

#### Setting popup effect


Go to `Admin Panel > Social Login > Settings > General`

Right after activating, all of available social buttons are shown on Sign In box while the page will appear instantly on Home page without any navigation to other site.

Admin can choose one of nice effects as you need by block in Popup Effect field.

![social popup effect](https://i.imgur.com/Bnv7qTn.png)

#### Custom color of checkbox


Go to `Admin Panel > Social Login > Settings > General`

Social Login by Mageplaza provides a Magento default color and **8** popular colors for your design, you can choose custom color which fit with your store design.

![social color](https://i.imgur.com/kZTaFjX.png)

Especially, now we also support you 9th color that you can freely custom depends on needs of yourself. It is unlimited color to design the style of Sign In box

![custom color social login](https://i.imgur.com/o1Ggu8F.png)

#### Facebook Sign in


##### How to configure Facebook


Go to `Admin Panel > Social Login > Settings > Facebook`

![config facebook login](https://i.imgur.com/wBtVqY9.png)

* Choose Yes or No to enable or disable Facebook Sign In button on the front-end with Facebook App ID and Facebook App Secret.

* If customers login via Facebook App, you can send email notification about their account’s password on your site or not, that depends on setting in Send Password to Customer field.

##### Login using Facebook


![login facebook](https://i.imgur.com/5zYCdnw.png)

The login box will display as popup checkbox after clicking on Facebook Sign In button.

#### Google Sign In


##### How to configure Google


Go to `Admin Panel > Social Login > Settings > Google`

![google login](https://i.imgur.com/jB6A0t1.png)

* Choose Yes or No to enable or disable Google Sign In button on the front-end with Client ID and Client Secret.

* If customers login via Google, you can send email notification about their account’s password on your site or not, that depends on setting in Send Password to Customer field.

#### Login using Google


![Google login](https://i.imgur.com/htWnJ7p.png)

The login box will display as popup checkbox after clicking on Google Sign In button.

#### Azure B2C Sign In
* Note that just now you need to use a branch of hybridauth to allow this to work.

![Branch of Hybridauth](https://github.com/ParamountVentures/hybridauth/tree/b2c-beta)

* Also note - when you use B2C, all other social channels are disabled as it is assumed you 
will be configuring them via B2C rather than Magento.

##### How to configure Azure B2C

* Create a "Web App / Web API" application your Azure B2C Tenant
* Set the reply Url to https://domain.com/sociallogin/social/callback/b2c.php
* Ensure the API access includes the openid scope
* Save the ClientId and Client Secret
* Create (or use the default) sign in policy and configure the claims you wish to return

Back in Magento:
* Go to `Admin Panel > Social Login > Settings > B2C`
* Set the Client Id to the above value
* Set the Client Secret to the above value
* Set your tenant name (i.e. the bit [tenant].onmicrosoft.com)
* Set the name of policy you have configured the claims to return
* Set the name of a campaign you have configured

#### Twitter Sign In


##### How to configure Twitter


Go to `Admin Panel > Social Login > Settings > Twitter`

![twitter login](https://i.imgur.com/9SRcWbU.png)

* Choose Yes or No to enable or disable Twitter Sign In button on the front-end with Consumer Key and Consumer Secret.

* If customers login via Twitter, you can send email notification about their account’s password on your site or not, that depends on setting in Send Password to Customer field.

##### Login using Twitter


![twitter social login](https://i.imgur.com/fYF1sRc.png)

The login box will display as popup checkbox after clicking on Twitter Sign In button.

#### LinkedIn Sign In


##### How to configure LinkedIn


Go to `Admin Panel > Social Login > Settings > LinkedIn`

![linkedin login](https://i.imgur.com/SqCKAB7.png)

* Choose Yes or No to enable or disable LikedIn Sign In button on the front-end with API Key and Client Key.

* If customers login via LinkedIn, you can send email notification about their account’s password on your site or not, that depends on setting in Send Password to Customer field.

##### Login using LinkedIn


![linkedin social login](https://i.imgur.com/IKERf5H.png)

The login box will display as popup checkbox after clicking on LinkedIn Sign In button.

#### Instagram Sign In


##### How to configure Instagram


Go to `Admin Panel > Social Login > Settings > Instagram`

![instagram](http://i.imgur.com/Pahpc6R.png)

* Choose Yes or No to enable or disable Instagram Sign In button on the front-end with Client ID and Client Secret.

* If customers login via Instagram, you can send email notification about their account’s password on your site or not, that depends on setting in Send Password to Customer field.

##### Login using Instagram

![instagram login](https://i.imgur.com/ha2CxQ0.png)

The login box will display as popup checkbox after clicking on Instagram Sign In button.




## 5. CHANGELOG 

### Social Login v2.3.7
Released on  2017-08-09
Release notes: 

+ Compatible with theme YourStore theme



### Social Login v2.3.6
Released on  2017-06-30
Release notes: 





### Social Login v2.3.5
Released on  2017-05-09
Release notes: 

- Fix bug CMS page has wrong page title after install social login



### Social Login v2.3.4
Released on  2017-05-08
Release notes: 

- Fix mistake when calling Amazon auth class



### Social Login 2.3.3
Released on  2017-04-25
Release notes: 

- Hotfix Facebook login returns HTTP ERROR 500 (#32)



### Social Login v2.3.2
Released on  2017-04-21
Release notes: 

- Fix bug compile error on Amazon login
- Allow admin choose popup login link selector



### Social Login 2.3.1
Released on  2017-04-20
Release notes: 

- Add Amazon Login
- Code optimization
- Fix some small minor bugs



### Social Login 2.2.0
Released on  2017-04-12
Release notes: 

- Optimize js code Use only jQuery library (remove prototype)
- Include the latest version of the Hybridauth library. (require via composer)
- Use bootstrap and font answer some to display social buttons

**Fix bugs**

   + Facebook Login httpsgithub.commageplazamagento-2-social-loginissues18 httpsgithub.commageplazamagento-2-social-loginissues4
   + Google Login httpsgithub.commageplazamagento-2-social-loginissues9

**Added Features**

   + Add social button to authentication popup httpsgithub.commageplazamagento-2-social-loginissues13
   + Can select the pages to display social buttons
   + Can enabledisable Popup Login



### Social Login v2.1.0
Released on  2017-04-09
Release notes: 

- Improve performance
- Fix Facebook login
- Upgrade hybridauth



### Social Login v2.0.4
Released on  2016-12-13
Release notes: 

- Hot fix 400. That’s an error. Error redirect_uri_mismatch





## Mageplaza extensions on Magento Marketplace, Github


☞ [Magento 2 One Step Checkout extension](https://marketplace.magento.com/mageplaza-magento-2-one-step-checkout-extension.html)

☞ [Magento 2 SEO Module](https://marketplace.magento.com/mageplaza-magento-2-seo-extension.html)

☞ [Magento 2 Blog extension](https://marketplace.magento.com/mageplaza-magento-2-blog-extension.html)

☞ [Magento 2 Layered Navigation extension](https://marketplace.magento.com/mageplaza-layered-navigation-m2.html)

☞ [Magento One Step Checkout](https://github.com/magento-2/one-step-checkout)

☞ [Magento 2 Blog on Github](https://github.com/mageplaza/magento-2-blog)

☞ [Magento 2 Social Login on Github](https://github.com/mageplaza/magento-2-social-login)

☞ [Magento 2 SEO on Github](https://github.com/mageplaza/magento-2-seo)

☞ [Magento 2 SMTP on Github](https://github.com/mageplaza/magento-2-smtp)

☞ [Magento 2 Product Slider on Github](https://github.com/mageplaza/magento-2-product-slider)

☞ [Magento 2 Banner on Github](https://github.com/mageplaza/magento-2-banner-slider)




