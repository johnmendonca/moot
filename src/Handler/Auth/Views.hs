module Handler.Auth.Views where

import Import

import Helpers.Views

renderSignup :: Widget -> [Text] -> Handler Html
renderSignup widget formErrors = do
  baseLayout Nothing $ do
    setTitle "Signup"
    [whamlet|
<article .grid-container>
  <div .grid-x .grid-margin-x>
    <div .medium-6 .cell>
      <h1>Signup for an account!
      $if not (null formErrors)
        <div data-abide-error
             class="alert callout">
            <p>
              <i class="fi-alert"></i>
              $forall errMsg <- formErrors
                <span.error>#{errMsg}
      <div>
        <form method="POST" action="@{SignupR}">
          ^{widget}
          <input .button type="submit" value="Submit">
|]

renderLogin :: Widget -> [Text] -> Handler Html
renderLogin widget formErrors = do
  baseLayout Nothing $ do
    setTitle "Login"
    [whamlet|
<article .grid-container>
  <div .grid-x .grid-margin-x>
    <div .medium-6 .cell>
      <h1>Log into Moot
      $if not (null formErrors)
        <div data-abide-error
             class="alert callout">
            <p>
              <i class="fi-alert"></i>
              $forall errMsg <- formErrors
                <span.error>#{errMsg}
      <div>
        <form action="@{LoginR}" method="POST">
          ^{widget}
          <div .text-right>
            <a href="@{ForgotR}">Forgot Password
          <p>
            <input .button data-disable-with="Login" name="commit" type="submit" value="Login">
|]

renderForgot :: Widget -> [Text] -> Handler Html
renderForgot widget formErrors = do
  baseLayout Nothing $ do
    setTitle "Forgot Password"
    [whamlet|
<article .grid-container>
  <div .grid-x .grid-margin-x>
    <div .medium-6 .cell>
      <h1>Forgot Password
      $if not (null formErrors)
        <div data-abide-error
             class="alert callout">
            <p>
              <i class="fi-alert"></i>
              $forall errMsg <- formErrors
                <span.error>#{errMsg}
      <div>
        <form method="POST" action="@{ForgotR}">
          ^{widget}
          <input .button type="submit" value="Submit">
|]

renderReset :: Widget -> Text -> [Text] -> Handler Html
renderReset widget token formErrors = do
  baseLayout Nothing $ do
    setTitle "Reset Password"
    [whamlet|
<article .grid-container>
  <div .grid-x .grid-margin-x>
    <div .medium-6 .cell>
      <h1>Reset Password
      $if not (null formErrors)
        <div data-abide-error
             class="alert callout">
            <p>
              <i class="fi-alert"></i>
              $forall errMsg <- formErrors
                <span.error>#{errMsg}
      <div>
        <form method="POST" action="@{ResetR token}">
          ^{widget}
          <input .button type="submit" value="Submit">
|]

renderNotice :: Text -> [Text] -> Handler Html
renderNotice header messages = do
  baseLayout Nothing $ do
    [whamlet|
<article .grid-container>
  <div .grid-x .grid-margin-x>
    <div .medium-6 .cell>
      <h1>#{header}
      $if not (null messages)
        <div data-abide-error
             class="success callout">
            <p>
              <i class="fi-alert"></i>
              $forall msg <- messages
                <span>#{msg}
|]

