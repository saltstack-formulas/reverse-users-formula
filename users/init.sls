#!py

class SshAuth:
  """Generates salt ssh_auth states based on pillar data.
  The data must be passed in one user at time and should already have
  date for the user created from the UserState class. The pillar format should be:
  users:
    example.user:
      userinfo:
      - public-keys:
        - salt://users/ssh-keys/example.user.pub
      present:
        G@example:match:
          - public-keys:
            - salt://users/ssh-keys/example.user.override.pub

  The match sections accept standard salt compound matches.
  public-keys under the match sections override what is in the userinfo section.
  """
  def __init__(self):
    self._sshStateDict = {}

  def _generateStates(self, user, existingStates, publicKeys):
    #Creates the ssh_auth state
    keyCount = 0
    for key in publicKeys:
      existingStates[user + "-pubkey-" + str(keyCount)] = {"ssh_auth.present": [{"user": user},
                                                            {"source": key},
                                                            {"require": [{"user": user}]}]}
      keyCount += 1

    return existingStates

  def appendStates(self, user, userState, existingStates):
    """Applies properly formatted ssh_auth state dictionaries to an existing dictionary
    containing user state data from the UserState class.
    """
    if len(userState) > 0:
      if userState.keys()[0] == "user.present":
        for option in userState["user.present"]:
          if option.keys()[0] == "public-keys":
            self._generateStates(user, existingStates, option["public-keys"])

#Class for generating user states based on the contents of the users pillar
class UserState:
  """Generates salt users states based on pillar data.
  The data must be passed in one user at a time with the format:
  users:
    example.user:
      userinfo:
        - fullname: Example User
        - shell: /bin/bash
      present:
        G@example:match:
          - shell: /bin/false

  The match sections accept standard salt compound matches.
  User state options under the match sections override what is in the userinfo section.
  """
  def __init__(self):
    self._userStateDict = {}

  def _applyOptionOverrides(self, overrideOption, userinfo):
    # Applies override user options specified under the match sections
    newUserList = []

    # First process the override options in the match sections
    for option in overrideOption:
      newUserList.append(overrideOption)

    # Then process the regular userinfo options excluding what was in the match sections
    for option in userinfo:
      if option.keys()[0] != overrideOption.keys()[0]:
        newUserList.append(option)

    return newUserList

  def _createOrRemoveUsers(self, matches, userinfo):

    state = ""
    
    if self._matchMinion(matches["absent"]):
      state = "absent"
    elif self._matchMinion(matches["present"]):
      state = "present"

    # If the current minion matches, create user states from user info and match overrides
    if state:
      for match in matches[state]:
        if __salt__["match.compound"](match) and matches[state][match] != None:
          for option in matches[state][match]:
            userinfo = self._applyOptionOverrides(option, userinfo)
      return { "user." + state: userinfo }

  def _matchMinion(self, matches, option={}):
    # Makes sure the current minion applies to the specified matches
    if matches is not None:
      for match in matches:
        if __salt__["match.compound"](match):
          return True
    return False

  def _getMatches(self, userData, presentOrAbsent):
    return userData.get(presentOrAbsent)

  def create(self, userData):
    """Returns a properly formatted salt user state dictionary object"""
    self._userStateDict = {}

    userinfo = userData.get("userinfo", []) or []

    matches = {}
    matches["present"] = self._getMatches(userData, "present")
    matches["absent"] = self._getMatches(userData, "absent")
    
    # Enforce present or absent users
    self._userStateDict = self._createOrRemoveUsers(matches, userinfo) or {}
    return self._userStateDict

def run():
  states = {}
  userState = UserState()
  sshAuth = SshAuth()

  # Create the user and ssh auth states a user at a time
  for user in __pillar__["users"]:
    # Prevent the creation of blank user states. This can cause id conflicts.
    tempState = userState.create(__pillar__["users"][user])

    if len(tempState) > 0:
      states[user] = tempState
      sshAuth.appendStates(user, states[user], states)

  return states 
