;; Copyright © 2022, JUXT LTD.

#_(remove-ns 'juxt.pass.v3.authorization-explainer-test)

(ns juxt.pass.v3.authorization-explainer-test
  (:require
   [clojure.test :refer [deftest is are use-fixtures] :as t]
   [juxt.pass.alpha.v3.authorization :as authz]
   [juxt.test.util :refer [with-xt submit-and-await! *xt-node*]]
   [xtdb.api :as xt]
   [clojure.set :as set]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'pass.malli (create-ns 'juxt.pass.alpha.malli))
(alias 'site (create-ns 'juxt.site.alpha))

(use-fixtures :each with-xt)

;; First, we define the actors.

;; Site is a 'Bring Your Own Domain' thing, and it's common for domains to
;; define users in terms of the attributes of those users that are important to
;; the domain. So in this example we define our users without any keywords that
;; would be recognisable to site/pass.

;; Note: if you're not familiar with the Alice and Bob characters, see
;; https://en.wikipedia.org/wiki/Alice_and_Bob#Cast_of_characters

(def ALICE
  {:xt/id "https://example.org/people/alice"
   ::type "Person"
   ::username "alice"})

(def BOB
  {:xt/id "https://example.org/people/bob"
   ::type "Person"
   ::username "bob"})

(def CARLOS
  {:xt/id "https://example.org/people/carlos"
   ::type "Person"
   ::username "carlos"})

(def FAYTHE
  {:xt/id "https://example.org/people/faythe"
   ::type "Person"
   ::username "faythe"})

(def OSCAR
  {:xt/id "https://example.org/people/oscar"
   ::type "Person"
   ::username "oscar"})

;; Applications. Applications access APIs on behalf of subjects. In most cases,
;; you can't access an API, certainly not a private one, without an application.

(def USER_APP
  {:xt/id "https://example.org/_site/apps/user"
   ::name "User App"
   ::pass/client-id "100"
   ::pass/client-secret "SecretUmbrella"
   ::pass/scope #{"read:resource" "write:resource"
                  "read:user"
                  "read:messages"
                  "read:health"}})

;; Subjects incorporate information about the person and other details. For
;; example, the device they are using, the method of authentication (whether
;; using 2FA), the level their claims can be trusted. Subjects are established
;; and stored in the user's session.

(def ALICE_SUBJECT
  {:xt/id "https://example.org/subjects/alice"
   ::person (:xt/id ALICE)
   ::email-verified true})

(def ALICE_UNVERIFIED_SUBJECT
  {:xt/id "https://example.org/subjects/unverified-alice"
   ::person (:xt/id ALICE)
   ::email-verified false})

(def BOB_SUBJECT
  {:xt/id "https://example.org/subjects/bob"
   ::person (:xt/id BOB)})

(def CARLOS_SUBJECT
  {:xt/id "https://example.org/subjects/carlos"
   ::person (:xt/id CARLOS)})

(def FAYTHE_SUBJECT
  {:xt/id "https://example.org/subjects/faythe"
   ::person (:xt/id FAYTHE)})

(def OSCAR_SUBJECT
  {:xt/id "https://example.org/subjects/oscar"
   ::person (:xt/id OSCAR)})

;; All access is via an access token. Access tokens reference the application
;; being used and the subject that the application is acting on behalf
;; of. Access tokens are Site documents and must contain, at the minimum,
;; ::site/type, ::pass/subject and ::pass/application-client. An access token
;; might not be granted all the scopes that the application requests. When the
;; access token's scopes are limited with respect to the application's allowed
;; scopes, a :pass/scope entry is added. This might be added at the creation of
;; the access token, or during its lifecycle (if the person represented by the
;; subject wishes to adjust the scope of the access token).

(def ALICE_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/alice"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id ALICE_SUBJECT)
   ::pass/application-client (:xt/id USER_APP)})

(def ALICE_READONLY_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/alice-readonly"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id ALICE_SUBJECT)
   ::pass/application-client (:xt/id USER_APP)
   ::pass/scope (set
                 (filter
                  #(re-matches #"read:.*" %)
                  (::pass/scope USER_APP)))})

(def BOB_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/bob"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id BOB_SUBJECT)
   ::pass/application-client (:xt/id USER_APP)})

(def CARLOS_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/carlos"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id CARLOS_SUBJECT)
   ::pass/application-client (:xt/id USER_APP)})

(def FAYTHE_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/faythe"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id FAYTHE_SUBJECT)
   ::pass/application-client (:xt/id USER_APP)})

(def OSCAR_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/oscar"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id OSCAR_SUBJECT)
   ::pass/application-client (:xt/id USER_APP)})

;; TODO: INTERNAL classification, different security models, see
;; https://en.m.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model
;; PUBLIC

(def EMPLOYEE_LIST
  {:xt/id "https://example.org/employees/"
   ::pass/classification "INTERNAL"})

(def LOGIN_PAGE
  {:xt/id "https://example.org/login"
   ::pass/classification "PUBLIC"})

;; Neither Alice nor Carlos can see this resource because it doesn't have an
;; explicit classification.
(def UNCLASSIFIED_PAGE
  {:xt/id "https://example.org/sales-report.csv"})

(def ANONYMOUS_SUBJECT
  {:xt/id "https://example.org/subjects/anonymous"})

(def ANONYMOUS_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/anonymous"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id ANONYMOUS_SUBJECT)
   ;; This might be the 'web client app' as part of the 'web-server pack'
   ::pass/application-client (:xt/id USER_APP)})

;; Alice is an employee
;; Carlos isn't an employee, but can access the login page

;; This action might come as part of a 'web-server' capability 'pack' where Site
;; would 'know' that all GET requests to a resource would involve this specific
;; action.
(def GET_RESOURCE
  {:xt/id "https://example.org/_site/actions/get-resource"
   ::site/type "Action"
   ::pass/scope "read:resource"
   ::pass/rules
   '[
     ;; Anyone can read PUBLIC resources
     [(allowed? permission access-token action resource)
      [resource ::pass/classification "PUBLIC"]
      [permission :xt/id]
      [access-token :xt/id]
      ]

     ;; Only persons granted permission to read INTERNAL resources
     [(allowed? permission access-token action resource)
      [resource ::pass/classification "INTERNAL"]
      [permission :xt/id]
      [access-token :xt/id]
      [permission ::person person]
      [access-token ::pass/subject subject]
      [subject ::person person]
      ]]})

(def ANYONE_CAN_READ_PUBLIC_RESOURCES
  {:xt/id "https://example.org/permissions/anyone-can-read-public-resources"
   ::site/type "Permission"
   ::pass/action (:xt/id GET_RESOURCE)
   ::pass/purpose nil})

(def ALICE_CAN_READ_INTERNAL_RESOURCES
  {:xt/id "https://example.org/permissions/alice-can-read-internal-resources"
   ::site/type "Permission"
   ::pass/action (:xt/id GET_RESOURCE)
   ::pass/purpose nil
   ::person (:xt/id ALICE)})

(deftest classified-resource-test
  (submit-and-await!
   [
    ;; Actors
    [::xt/put ALICE]
    [::xt/put CARLOS]

    ;; Actions
    [::xt/put GET_RESOURCE]

    ;; Subjects
    [::xt/put ALICE_SUBJECT]
    [::xt/put CARLOS_SUBJECT]
    [::xt/put ANONYMOUS_SUBJECT]

    ;; Access tokens
    [::xt/put ALICE_ACCESS_TOKEN]
    [::xt/put CARLOS_ACCESS_TOKEN]
    [::xt/put ANONYMOUS_ACCESS_TOKEN]

    ;; Resources
    [::xt/put LOGIN_PAGE]
    [::xt/put EMPLOYEE_LIST]

    ;; Permissions
    [::xt/put ANYONE_CAN_READ_PUBLIC_RESOURCES]
    [::xt/put ALICE_CAN_READ_INTERNAL_RESOURCES]])

  (let [db (xt/db *xt-node*)]
    (are [access-token resource expected]
        (let [permissions
              (authz/check-permissions
               db {:actions #{(:xt/id GET_RESOURCE)}
                   :resource (:xt/id resource)
                   :scope #{"read:resource"}
                   :access-token (:xt/id access-token)
                   :rules (authz/actions->rules db #{(:xt/id GET_RESOURCE)})})]
          (if expected
            (is (seq permissions))
            (is (not (seq permissions)))))

      ALICE_ACCESS_TOKEN LOGIN_PAGE true
      ALICE_ACCESS_TOKEN EMPLOYEE_LIST true

      CARLOS_ACCESS_TOKEN LOGIN_PAGE true
      CARLOS_ACCESS_TOKEN EMPLOYEE_LIST false

      ANONYMOUS_ACCESS_TOKEN LOGIN_PAGE true
      ANONYMOUS_ACCESS_TOKEN EMPLOYEE_LIST false)))


#_((t/join-fixtures [with-xt])
  (fn []
))

;; User directories

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/actions/resources.

;; TODO: Not a great first example! Try something easier to start with.

(def ALICE_USER_DIR_PRIVATE_FILE
  {:xt/id "https://example.org/~alice/private.txt"})

(def ALICE_USER_DIR_SHARED_FILE
  {:xt/id "https://example.org/~alice/shared.txt"})

(def READ_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/read-user-dir"
   ::site/type "Action"
   ::pass/scope "read:resource"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/rules
   '[[(allowed? permission access-token action resource)
      [action ::pass/resource-matches resource-regex]
      [access-token ::pass/subject subject]
      [permission ::person person]
      [subject ::person person]
      [person ::type "Person"]
      [resource :xt/id]
      [person ::username username]
      [(re-pattern resource-regex) resource-pattern]
      [(re-matches resource-pattern resource) [_ user]]
      [(= user username)]]]})

(def WRITE_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/write-user-dir"
   ::site/type "Action"
   ::pass/scope "write:resource"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/action-args [{}]
   ::pass/rules
   '[[(allowed? permission access-token action resource)
      [action ::pass/resource-matches resource-regex]
      [access-token ::pass/subject subject]
      [permission ::person person]
      [subject ::person person]
      [person ::type "Person"]
      [person ::username username]
      [(re-pattern resource-regex) resource-pattern]
      [(re-matches resource-pattern resource) [_ user]]
      [(= user username)]]]})

(def READ_SHARED_ACTION
  {:xt/id "https://example.org/actions/read-shared"
   ::site/type "Action"
   ::pass/scope "read:resource"
   ::pass/rules
   '[[(allowed? permission access-token action resource)
      [access-token ::pass/subject subject]
      [permission ::person person]
      [person ::type "Person"]
      [subject ::person person]
      [resource :xt/id]
      [permission ::pass/resource resource]]]})

(def ALICE_CAN_READ
  {:xt/id "https://example.org/permissions/alice-can-read"
   ::site/type "Permission"
   ::person "https://example.org/people/alice"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}
   ::pass/purpose nil})

(def ALICE_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/alice-can-write-user-dir-content"
   ::site/type "Permission"
   ::person "https://example.org/people/alice"
   ::pass/action "https://example.org/actions/write-user-dir"
   ::pass/purpose nil})

(def BOB_CAN_READ
  {:xt/id "https://example.org/permissions/bob-can-read"
   ::site/type "Permission"
   ::person "https://example.org/people/bob"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}
   ::pass/purpose nil})

(def ALICES_SHARES_FILE_WITH_BOB
  {:xt/id "https://example.org/permissions/alice-shares-file-with-bob"
   ::site/type "Permission"
   ::person "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/read-shared"
   ::pass/purpose nil
   ::pass/resource "https://example.org/~alice/shared.txt"})

(def BOB_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/bob-can-write-user-dir-content"
   ::site/type "Permission"
   ::person "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/write-user-dir"
   ::pass/purpose nil})

;; Scopes. Actions inhabit scopes.

(defn effective-scope [db access-token]
  (let [access-token-doc (xt/entity db access-token)
        _ (assert access-token-doc)
        app (xt/entity db (::pass/application-client access-token-doc))
        _ (assert app)
        scope (::pass/scope app)
        _ (assert scope)
        access-token-scope (::pass/scope access-token-doc)]
    (cond-> scope
      access-token-scope (set/intersection access-token-scope))))

(deftest user-dir-test
  (submit-and-await!
   [
    ;; Applications
    [::xt/put USER_APP]

    ;; Subjects
    [::xt/put ALICE]
    [::xt/put ALICE_SUBJECT]
    [::xt/put BOB]
    [::xt/put BOB_SUBJECT]
    [::xt/put CARLOS]
    [::xt/put CARLOS_SUBJECT]

    ;; Access tokens
    [::xt/put ALICE_ACCESS_TOKEN]
    [::xt/put ALICE_READONLY_ACCESS_TOKEN]
    [::xt/put BOB_ACCESS_TOKEN]
    [::xt/put CARLOS_ACCESS_TOKEN]

    ;; Actions
    [::xt/put READ_USER_DIR_ACTION]
    [::xt/put READ_SHARED_ACTION]
    [::xt/put WRITE_USER_DIR_ACTION]

    ;; Resources
    [::xt/put ALICE_USER_DIR_PRIVATE_FILE]
    [::xt/put ALICE_USER_DIR_SHARED_FILE]

    ;; Permissions
    [::xt/put ALICE_CAN_READ]
    [::xt/put ALICE_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put BOB_CAN_READ]
    [::xt/put BOB_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put ALICES_SHARES_FILE_WITH_BOB]])

  (let [db (xt/db *xt-node*)]
    (are [access-token actions resource ok?]
        (let [rules (authz/actions->rules db actions)
              scope (effective-scope db access-token)
              actual (authz/check-permissions
                      db {:access-token access-token
                          :scope scope
                          :actions actions
                          :resource resource
                          :rules rules})]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can read her own private file.
        "https://example.org/tokens/alice"
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/private.txt"
        true

        ;; Alice can read the file in her user directory which she has shared with
        ;; Bob.
        "https://example.org/tokens/alice"
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/shared.txt"
        true

        ;; Bob cannot read Alice's private file.
        "https://example.org/tokens/bob"
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/private.txt"
        false

        ;; Bob can read the file Alice has shared with him.
        "https://example.org/tokens/bob"
        #{"https://example.org/actions/read-shared"}
        "https://example.org/~alice/shared.txt"
        true

        ;; Alice can put a file to her user directory
        "https://example.org/tokens/alice"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~alice/foo.txt"
        true

        ;; Alice can't put a file to her user directory without write:resource
        ;; scope
        "https://example.org/tokens/alice-readonly"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~alice/foo.txt"
        false

        ;; Alice can't put a file to Bob's user directory
        "https://example.org/tokens/alice"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~bob/foo.txt"
        false

        ;; Alice can't put a file outside her user directory
        "https://example.org/tokens/alice"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/index.html"
        false

        ;; Bob can put a file to his user directory
        "https://example.org/tokens/bob"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~bob/foo.txt"
        true

        ;; Bob can't put a file to Alice's directory
        "https://example.org/tokens/bob"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~alice/foo.txt"
        false

        ;; Carlos cannot put a file to his user directory, as he hasn't been
        ;; granted the write-user-dir action.
        "https://example.org/tokens/carlos"
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~carlos/foo.txt"
        false
        )

    (are [access-token actions expected]
        (let [rules (authz/actions->rules db actions)
              scope (effective-scope db access-token)]
          (is (= expected
                 (authz/allowed-resources
                  db
                  {:access-token access-token
                   :scope scope
                   :actions actions
                   :rules rules}))))

      ;; Alice can see all her files.
        "https://example.org/tokens/alice"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{["https://example.org/~alice/shared.txt"]
          ["https://example.org/~alice/private.txt"]}

        ;; Bob can only see the file Alice has shared with him.
        "https://example.org/tokens/bob"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{["https://example.org/~alice/shared.txt"]}

        ;; Carlos sees nothing
        "https://example.org/tokens/carlos"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{})

    ;; Given a resource and a set of actions, which subjects can access
    ;; and via which actions?

    (are [resource actions scope expected]
        (let [rules (authz/actions->rules db actions)]
          (is (= expected (authz/allowed-subjects
                           db
                           {:resource resource
                            :actions actions
                            :scope scope
                            :rules rules}))))

        "https://example.org/~alice/shared.txt"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{"read:resource"}
        #{{:subject "https://example.org/subjects/bob",
           :action "https://example.org/actions/read-shared"}
          {:subject "https://example.org/subjects/alice",
           :action "https://example.org/actions/read-user-dir"}}

        "https://example.org/~alice/private.txt"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{"read:resource"}
        #{{:subject "https://example.org/subjects/alice",
           :action "https://example.org/actions/read-user-dir"}}

        ;; Cannot see anything without a scope
        "https://example.org/~alice/shared.txt"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{}
        #{})))

(deftest constrained-pull-test
  (let [READ_USERNAME_ACTION
        {:xt/id "https://example.org/actions/read-username"
         ::site/type "Action"
         ::pass/scope "read:user"
         ::pass/pull [::username]}

        READ_SECRETS_ACTION
        {:xt/id "https://example.org/actions/read-secrets"
         ::site/type "Action"
         ::pass/scope "read:user"
         ::pass/pull [::secret]}

        BOB_CAN_READ_ALICE_USERNAME
        {:xt/id "https://example.org/permissions/bob-can-read-alice-username"
         ::site/type "Permission"
         ::person "https://example.org/people/bob"
         ::pass/action "https://example.org/actions/read-username"
         ::pass/purpose nil
         ::pass/resource "https://example.org/people/alice"}

        BOB_CAN_READ_ALICE_SECRETS
        {:xt/id "https://example.org/permissions/bob-can-read-alice-secrets"
         ::site/type "Permission"
         ::person "https://example.org/people/bob"
         ::pass/action "https://example.org/actions/read-secrets"
         ::pass/purpose nil
         ::pass/resource "https://example.org/people/alice"}

        CARLOS_CAN_READ_ALICE_USERNAME
        {:xt/id "https://example.org/permissions/carlos-can-read-alice-username"
         ::site/type "Permission"
         ::person "https://example.org/people/carlos"
         ::pass/action "https://example.org/actions/read-username"
         ::pass/purpose nil
         ::pass/resource "https://example.org/people/alice"}

        rules
        '[[(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/read-username"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [permission ::pass/resource resource]]

          [(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/read-secrets"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [permission ::pass/resource resource]]]]

    (submit-and-await!
     [
      ;; Actors
      [::xt/put (assoc ALICE ::secret "foo")]
      [::xt/put BOB]
      [::xt/put CARLOS]

      ;; Subjects
      [::xt/put ALICE_SUBJECT]
      [::xt/put BOB_SUBJECT]
      [::xt/put CARLOS_SUBJECT]

      ;; Access tokens
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put BOB_ACCESS_TOKEN]
      [::xt/put CARLOS_ACCESS_TOKEN]

      ;; Actions
      [::xt/put READ_USERNAME_ACTION]
      [::xt/put READ_SECRETS_ACTION]
      [::xt/put BOB_CAN_READ_ALICE_USERNAME]
      [::xt/put BOB_CAN_READ_ALICE_SECRETS]
      [::xt/put CARLOS_CAN_READ_ALICE_USERNAME]
      ])

    ;; Bob can read Alice's secret
    (let [db (xt/db *xt-node*)]
      (are [access-token expected]
          (let [actual
                (authz/pull-allowed-resource
                 db
                 {:access-token (:xt/id access-token)
                  :scope #{"read:user"}
                  :actions #{(:xt/id READ_USERNAME_ACTION) (:xt/id READ_SECRETS_ACTION)}
                  :resource (:xt/id ALICE)
                  :rules rules})]
            (is (= expected actual)))

        BOB_ACCESS_TOKEN {::username "alice" ::secret "foo"}
        CARLOS_ACCESS_TOKEN {::username "alice"}))))

(deftest pull-allowed-resources-test
  (let [READ_MESSAGE_CONTENT_ACTION
        {:xt/id "https://example.org/actions/read-message-content"
         ::site/type "Action"
         ::pass/scope "read:messages"
         ::pass/pull [::content]}

        READ_MESSAGE_METADATA_ACTION
        {:xt/id "https://example.org/actions/read-message-metadata"
         ::site/type "Action"
         ::pass/scope "read:messages"
         ::pass/pull [::from ::to ::date]}

        ALICE_BELONGS_GROUP_A
        {:xt/id "https://example.org/group/a/alice"
         ::site/type "Permission"
         ::person (:xt/id ALICE)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}
         ::pass/purpose nil}

        BOB_BELONGS_GROUP_A
        {:xt/id "https://example.org/group/a/bob"
         ::site/type "Permission"
         ::person (:xt/id BOB)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}
         ::pass/purpose nil}

        ;; Faythe is a trusted admin of Group A. She can see the metadata but
        ;; not the content of messages.
        FAYTHE_MONITORS_GROUP_A
        {:xt/id "https://example.org/group/a/faythe"
         ::site/type "Permission"
         ::person (:xt/id FAYTHE)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_METADATA_ACTION)}
         ::pass/purpose nil}

        rules
        '[[(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/read-message-content"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [permission ::group group]
           [resource ::group group]
           [resource ::site/type "Message"]]

          [(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/read-message-metadata"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [permission ::group group]
           [resource ::group group]
           [resource ::site/type "Message"]]]]

    (submit-and-await!
     [
      ;; Actions
      [::xt/put READ_MESSAGE_CONTENT_ACTION]
      [::xt/put READ_MESSAGE_METADATA_ACTION]

      ;; Actors
      [::xt/put ALICE]
      [::xt/put BOB]
      [::xt/put CARLOS]
      [::xt/put FAYTHE]

      ;; Subjects
      [::xt/put ALICE_SUBJECT]
      [::xt/put BOB_SUBJECT]
      [::xt/put CARLOS_SUBJECT]
      [::xt/put FAYTHE_SUBJECT]

      ;; Access tokens
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put BOB_ACCESS_TOKEN]
      [::xt/put CARLOS_ACCESS_TOKEN]
      [::xt/put FAYTHE_ACCESS_TOKEN]

      ;; Permissions
      [::xt/put ALICE_BELONGS_GROUP_A]
      [::xt/put BOB_BELONGS_GROUP_A]
      [::xt/put FAYTHE_MONITORS_GROUP_A]

      ;; Messages
      [::xt/put
       {:xt/id "https://example.org/messages/1"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id ALICE)
        ::to (:xt/id BOB)
        ::date "2022-03-07T13:00:00"
        ::content "Hello Bob!"}]

      [::xt/put
       {:xt/id "https://example.org/messages/2"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id BOB)
        ::to (:xt/id ALICE)
        ::date "2022-03-07T13:00:10"
        ::content "Hi Alice, how are you?"}]

      [::xt/put
       {:xt/id "https://example.org/messages/3"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id ALICE)
        ::to (:xt/id BOB)
        ::date "2022-03-07T13:00:20"
        ::content "Great thanks. I've reset your password, btw."}]

      [::xt/put
       {:xt/id "https://example.org/messages/4"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id BOB)
        ::to (:xt/id ALICE)
        ::date "2022-03-07T13:00:40"
        ::content "Thanks, what is it?"}]

      [::xt/put
       {:xt/id "https://example.org/messages/5"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id ALICE)
        ::to (:xt/id BOB)
        ::date "2022-03-07T13:00:50"
        ::content "It's 'BananaTree@1230', you should definitely change it at some point."}]

      [::xt/put
       {:xt/id "https://example.org/messages/6"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id BOB)
        ::to (:xt/id ALICE)
        ::date "2022-03-07T13:00:50"
        ::content "Thanks Alice, that's very kind of you - see you at lunch!"}]])

    (let [get-messages
          (fn [access-token]
            (authz/pull-allowed-resources
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:messages"}
              :actions #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}
              :rules rules}))]

      ;; Alice and Bob can read all the messages in the group
      (let [messages (get-messages ALICE_ACCESS_TOKEN)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date ::content} (set (keys (first messages))))))

      (let [messages (get-messages BOB_ACCESS_TOKEN)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date ::content} (set (keys (first messages))))))

      ;; Carlos cannot see any of the messages
      (is (zero? (count (get-messages CARLOS_ACCESS_TOKEN))))

      ;; Faythe can read meta-data of the conversation between Alice and Bob but
      ;; not the content of the messages.
      (let [messages (get-messages FAYTHE_ACCESS_TOKEN)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date} (set (keys (first messages))))))

      ;; We can specify an :include-rules entry to pull-allowed-resources to
      ;; restrict the resources that are found to some additional
      ;; criteria. Currently this is as close as we get to providing full query
      ;; capabilities.
      (is (= 3 (count
                (authz/pull-allowed-resources
                 (xt/db *xt-node*)
                 {:access-token (:xt/id ALICE_ACCESS_TOKEN)
                  :scope #{"read:messages"}
                  :actions #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                             (:xt/id READ_MESSAGE_METADATA_ACTION)}
                  :rules rules
                  :include-rules [['(include? access-token action message)
                                   ['message ::from (:xt/id ALICE)]]]})))))))

;; Alice has a medical record. She wants to allow Oscar access to it, but only
;; in emergencies (to provide to a doctor in case of urgent need).

;; One way of achieving this is to segment actions by purpose.

(deftest purpose-with-distinct-actions-test
  (let [READ_MEDICAL_RECORD_ACTION
        {:xt/id "https://example.org/actions/read-medical-record"
         ::site/type "Action"
         ::pass/scope "read:health"
         ::pass/pull ['*]
         ::pass/alert-log false}

        EMERGENCY_READ_MEDICAL_RECORD_ACTION
        {:xt/id "https://example.org/actions/emergency-read-medical-record"
         ::site/type "Action"
         ::pass/scope "read:health"
         ::pass/pull ['*]
         ::pass/alert-log true}

        rules
        '[[(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/read-medical-record"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [resource ::site/type "MedicalRecord"]]

          [(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/emergency-read-medical-record"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [resource ::site/type "MedicalRecord"]]]]

    (submit-and-await!
     [
      ;; Actors
      [::xt/put ALICE]
      [::xt/put OSCAR]

      ;; Subjects
      [::xt/put ALICE_SUBJECT]
      [::xt/put OSCAR_SUBJECT]

      ;; Access token
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put OSCAR_ACCESS_TOKEN]

      ;; Actions
      [::xt/put READ_MEDICAL_RECORD_ACTION]
      [::xt/put EMERGENCY_READ_MEDICAL_RECORD_ACTION]

      ;; Permissions
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record/grants/oscar"
        ::site/type "Permission"
        ::person (:xt/id OSCAR)
        ::pass/action #{(:xt/id EMERGENCY_READ_MEDICAL_RECORD_ACTION)}
        ::pass/purpose nil}]

      ;; Resources
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record"
        ::site/type "MedicalRecord"
        ::content "Medical info"}]])

    (let [get-medical-records
          (fn [access-token action]
            (authz/pull-allowed-resources
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :rules rules}))

          get-medical-record
          (fn [access-token action]
            (authz/pull-allowed-resource
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :resource "https://example.org/alice/medical-record"
              :rules rules}))]

      (is (zero? (count (get-medical-records OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION))))
      (is (= 1 (count (get-medical-records OSCAR_ACCESS_TOKEN EMERGENCY_READ_MEDICAL_RECORD_ACTION))))
      (is (not (get-medical-record OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION)))
      (is (get-medical-record OSCAR_ACCESS_TOKEN EMERGENCY_READ_MEDICAL_RECORD_ACTION)))))

;; An alternative way of achieving the same result is to specify a purpose when
;; granting a permission.

(deftest purpose-test
  (let [READ_MEDICAL_RECORD_ACTION
        {:xt/id "https://example.org/actions/read-medical-record"
         ::site/type "Action"
         ::pass/scope "read:health"
         ::pass/pull ['*]}

        rules
        '[[(allowed? permission access-token action resource)
           [action :xt/id "https://example.org/actions/read-medical-record"]
           [permission ::person person]
           [subject ::person person]
           [person ::type "Person"]
           [access-token ::pass/subject subject]
           [permission ::pass/purpose purpose]
           [resource ::site/type "MedicalRecord"]]]]

    (submit-and-await!
     [
      ;; Actors
      [::xt/put ALICE]
      [::xt/put OSCAR]

      ;; Subjects
      [::xt/put ALICE_SUBJECT]
      [::xt/put OSCAR_SUBJECT]

      ;; Access tokens
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put OSCAR_ACCESS_TOKEN]

      ;; Actions
      [::xt/put READ_MEDICAL_RECORD_ACTION]

      ;; Purposes
      [::xt/put
       {:xt/id "https://example.org/purposes/emergency"
        ::site/type "Purpose"
        ::description "Emergency access to vital personal information."
        ::gdpr-interest "VITAL"}]

      ;; Permissions
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record/grants/oscar"
        ::site/type "Permission"
        ::person (:xt/id OSCAR)
        ::pass/action (:xt/id READ_MEDICAL_RECORD_ACTION)
        ::pass/purpose "https://example.org/purposes/emergency"}]

      ;; Resources
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record"
        ::site/type "MedicalRecord"
        ::content "Medical info"}]])

    (let [get-medical-records
          (fn [access-token action purpose]
            (authz/pull-allowed-resources
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :purpose purpose
              :rules rules}))

          get-medical-record
          (fn [access-token action purpose]
            (authz/pull-allowed-resource
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :purpose purpose
              :resource "https://example.org/alice/medical-record"
              :rules rules}))]

      (is (zero? (count (get-medical-records OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/marketing"))))
      (is (= 1 (count (get-medical-records OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/emergency"))))

      (is (nil? (get-medical-record OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/marketing")))
      (is (get-medical-record OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/emergency")))))

;; Bootstrapping

;; TODO
;; Next up. Sharing itself. Is Alice even permitted to share her files?
;; read-only, read/write
;; Answer @jms's question: is it possible for Sue to grant a resource for
;; which she hasn't herself access?

(def SUE
  {:xt/id "https://example.org/people/sue"
   ::type "Person"
   ::username "sue"})

(def ADMIN_APP
  {:xt/id "https://example.org/_site/apps/admin"
   ::name "Admin App"
   ::pass/client-id "101"
   ::pass/client-secret "SecretArmadillo"
   ::pass/scope #{"read:admin" "write:admin"}})

(def SUE_SUBJECT
  {:xt/id "https://example.org/subjects/sue"
   ::person (:xt/id SUE)
   ::email-verified true})

(def SUE_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/sue"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id SUE_SUBJECT)
   ::pass/application-client (:xt/id ADMIN_APP)})

(def SUE_READONLY_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/sue-readonly"
   ::site/type "AccessToken"
   ::pass/subject (:xt/id SUE_SUBJECT)
   ::pass/application-client (:xt/id ADMIN_APP)
   ::pass/scope #{"read:admin"}})

(def CREATE_PERSON_ACTION
  {:xt/id "https://example.org/actions/create-person"
   ::site/type "Action"
   ::pass/scope "write:admin"
   ::pass/action-args
   [{::pass.malli/schema
     [:map
      [::type [:= "Person"]]
      [::username [:string]]]

     ::pass/process
     [
      ;; Though we could use a Malli value transformer here, at this stage is
      ;; doesn't feel beneficial to lean too heavily on Malli's extensive
      ;; feature set.
      [::pass/merge {::type "Person"}]
      [::pass.malli/validate]]}]})

(def CREATE_IDENTITY_ACTION
  {:xt/id "https://example.org/actions/create-identity"
   ::site/type "Action"
   ::pass/scope "write:admin"
   ::pass/action-args [{}]})

(deftest call-action-test
  (let [rules ['[(allowed? permission access-token action resource)
                 [action :xt/id "https://example.org/actions/create-person"]
                 [permission ::person person]
                 [subject ::person person]
                 [person ::type "Person"]
                 [access-token ::pass/subject subject]]]]
    (submit-and-await!
     [
      ;; Applications
      [::xt/put ADMIN_APP]

      ;; Actors
      [::xt/put SUE]
      [::xt/put CARLOS]

      ;; Subjects
      [::xt/put SUE_SUBJECT]
      [::xt/put CARLOS_SUBJECT]

      ;; Access tokens
      [::xt/put SUE_ACCESS_TOKEN]
      [::xt/put SUE_READONLY_ACCESS_TOKEN]
      [::xt/put CARLOS_ACCESS_TOKEN]

      ;; Actions
      [::xt/put CREATE_PERSON_ACTION]
      [::xt/put CREATE_IDENTITY_ACTION]

      ;; Permissions
      [::xt/put
       {:xt/id "https://example.org/permissions/sue/create-person"
        ::site/type "Permission"
        ::person (:xt/id SUE)
        ::pass/action (:xt/id CREATE_PERSON_ACTION)
        ::pass/purpose nil #_"https://example.org/purposes/bootsrapping-system"}]

      ;; Functions
      [::xt/put (authz/register-call-action-fn)]])

    ;; Sue creates the user Alice, with an identity
    (let [db (xt/db *xt-node*)]
      (is
       (seq
        (authz/check-permissions
         db
         (let [access-token (:xt/id SUE_ACCESS_TOKEN)]
           {:access-token access-token
            :scope (effective-scope db access-token)
            :actions #{(:xt/id CREATE_PERSON_ACTION)}
            :rules rules}))))
      (is
       (not
        (seq
         (authz/check-permissions
          db
          (let [access-token (:xt/id SUE_READONLY_ACCESS_TOKEN)]
            {:access-token access-token
             :scope (effective-scope db access-token)
             :actions #{(:xt/id CREATE_PERSON_ACTION)}
             :rules rules}))))))

    (authz/call-action!
     *xt-node*
     (let [access-token (:xt/id SUE_ACCESS_TOKEN)]
       {:access-token access-token
        :scope (effective-scope (xt/db *xt-node*) access-token)
        :action (:xt/id CREATE_PERSON_ACTION)
        :rules rules
        :args [{:xt/id ALICE ::username "alice"}]}))

    (is (xt/entity (xt/db *xt-node*) ALICE))

    ;; This fails because we haven't provided the ::username
    (is
     (thrown?
      AssertionError
      (authz/call-action!
       *xt-node*
       (let [access-token (:xt/id SUE_ACCESS_TOKEN)]
         {:access-token access-token
          :scope (effective-scope (xt/db *xt-node*) access-token)
          :action (:xt/id CREATE_PERSON_ACTION)
          :rules rules
          :args [{:xt/id ALICE}]}))))))

#_((t/join-fixtures [with-xt])
   (fn []
     :ok
     ))

;; TODO: Extend to GraphQL
;;
;; TODO: Subject access from 'inside' versus 'outside' the perimeter
;;
;; TODO: Continue bootstrapping so Alice can do stuff
;;
;; TODO: Create action list-persons which can be in the scope read:internal ?
;; Or can list-persons as an action be granted to INTERNAL?
;; Does list-persons refer to a resource? I suppose so, it's read:resource on /people/

;; Create a list-persons action
;; Create /people/ resource
;; Grant list-persons on /people/ to Alice
;; Can a GET from Alice to /people/ trigger a list-persons actions?
;; Can a list-persons action be configured to do a a query?

;; Things we'll need in the bootstrap
;;
;; Access token only
;;
;; * A user (can contain anything, just needs to exist)
;; * A OAuth2 registered application representing the 'admin app' (client-id and client-secret) that a caller will use when acquiring a token against the token endpoint
;; * Actions which belong to one or more scopes that permit authorized access to the database
;; * Permissions on the user
;; * Rules that reference permissions, access-tokens, actions and resources
;;
;; Adding an authorization-provider
;;
;; * An login endpoint that sets up the session and redirects to an issuer
;; * OpenID Authorization Server details (so we can do $issuer/.wellknown/openid-config)
;; * JWKS for the issuer
;; * An identity (::site/type "Identity") that links to a user (::site/user) and has a matching iss/sub
;; * OpenID Connect client application details that have been registered with the OpenID Authorization Server
;; * A callback endpoint for the application (this will update the session and set the cookie)
;; * A token endpoint that can be used to acquire tokens
